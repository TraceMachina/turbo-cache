// Copyright 2024 The NativeLink Authors. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use core::panic;
use std::any::Any;
use std::cell::RefCell;
use std::clone::Clone;
use std::collections::HashMap;
use std::mem::ManuallyDrop;
use std::pin::Pin;
use std::ptr::from_ref;
use std::sync::Arc;
use std::task::{Context, Poll};

use futures::Future;
use nativelink_error::{make_err, Code, Error};
use pin_project_lite::pin_project;
use tracing::instrument::Instrumented;
use tracing::{Instrument, Span};

use crate::background_spawn;

/// Make a symbol that represents a unique memory pointer that is
/// constant and chosen at compile time. This enables two modules
/// to use that memory location to reference data that lives in a
/// shared module without the two modules knowing about each other.
/// For example, let's say we have a context that holds anonymous
/// data; we can use these symbols to let one module set the data
/// and tie the data to a symbol and another module read the data
/// with the symbol, without the two modules knowing about each other.
#[macro_export]
macro_rules! make_symbol {
    ($name:ident, $type:ident) => {
        #[no_mangle]
        #[used]
        pub static $name: $crate::origin_context::NLSymbol<$type> =
            $crate::origin_context::NLSymbol {
                name: concat!(module_path!(), "::", stringify!($name)),
                _phantom: std::marker::PhantomData {},
            };
    };
}

// Symbol that represents the identity of the origin of a request.
// See: IdentityHeaderSpec for details.
make_symbol!(ORIGIN_IDENTITY, String);

pub struct NLSymbol<T: Send + Sync + 'static> {
    pub name: &'static str,
    pub _phantom: std::marker::PhantomData<T>,
}

impl<T: Send + Sync + 'static> Symbol for NLSymbol<T> {
    type Type = T;

    fn name(&self) -> &'static str {
        self.name
    }
}

pub type RawSymbol = std::os::raw::c_void;

pub trait Symbol {
    type Type: 'static;

    fn name(&self) -> &'static str {
        std::any::type_name::<Self>()
    }

    fn as_ptr(&'static self) -> *const RawSymbol {
        from_ref::<Self>(self).cast::<RawSymbol>()
    }
}

/// Simple wrapper around a raw symbol pointer.
/// This allows us to bypass the unsafe undefined behavior check
/// when using raw pointers by manually implementing Send and Sync.
#[derive(Eq, PartialEq, Hash, Clone)]
#[repr(transparent)]
pub struct RawSymbolWrapper(pub *const RawSymbol);

unsafe impl Send for RawSymbolWrapper {}
unsafe impl Sync for RawSymbolWrapper {}

/// Context used to store data about the origin of a request.
#[derive(Default, Clone)]
pub struct OriginContext {
    data: HashMap<RawSymbolWrapper, Arc<dyn Any + Send + Sync + 'static>>,
}

impl OriginContext {
    /// Creates a new (empty) context.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the value for a given symbol on the context.
    pub fn set_value<T: Any + Send + Sync + 'static>(
        &mut self,
        symbol: &'static impl Symbol<Type = T>,
        value: Arc<T>,
    ) -> Option<Arc<dyn Any + Send + Sync + 'static>> {
        self.data.insert(RawSymbolWrapper(symbol.as_ptr()), value)
    }

    /// Gets the value current set for a given symbol on the context.
    #[inline]
    pub fn get_value<T: Send + Sync + 'static>(
        &self,
        symbol: &'static impl Symbol<Type = T>,
    ) -> Result<Option<Arc<T>>, Error> {
        self.data
            .get(&RawSymbolWrapper(symbol.as_ptr()))
            .map_or(Ok(None), |value| {
                Arc::downcast::<T>(value.clone()).map_or_else(
                    |_| {
                        Err(make_err!(
                            Code::Internal,
                            "Failed to downcast symbol: {}",
                            symbol.name(),
                        ))
                    },
                    |v| Ok(Some(v)),
                )
            })
    }

    /// Consumes the context and runs the given function with the context set
    /// as the active context. When the function exits, the context is restored
    /// to the previous global context.
    #[inline]
    pub fn run<T>(self, span: Span, func: impl FnOnce() -> T) -> T {
        Arc::new(self).wrap(span, func)()
    }

    /// Wraps a function so when it is called the passed in context is set as
    /// the active context and when the function exits, the context is restored
    /// to the previous global context.
    #[inline]
    fn wrap<T>(self: Arc<Self>, span: Span, func: impl FnOnce() -> T) -> impl FnOnce() -> T {
        move || {
            let enter = Self::enter(self);
            let result = span.in_scope(func);
            enter.release();
            result
        }
    }

    /// Wraps a future so when it is called the passed in context is set as
    /// the active context and when the future exits, the context is restored
    /// to the previous global context.
    #[inline]
    pub fn wrap_async<T>(
        self: Arc<Self>,
        span: Span,
        fut: impl Future<Output = T>,
    ) -> impl Future<Output = T> {
        ContextAwareFuture::new(Some(self), fut.instrument(span))
    }

    /// Spawns a future in the background with the given context.
    pub fn background_spawn(
        self: Arc<Self>,
        span: Span,
        fut: impl Future<Output = ()> + Send + 'static,
    ) {
        background_spawn!(span: span, ctx: Some(self), fut: fut);
    }

    /// Enters the context, storing the previous context. If the returned
    /// `ContextDropGuard` is dropped, the previous context is restored.
    #[inline]
    fn enter(self: Arc<Self>) -> ContextDropGuard {
        ContextDropGuard::new(self)
    }
}

/// Static struct to interact with the active global context.
pub struct ActiveOriginContext;

impl ActiveOriginContext {
    /// Sets the active context for the current thread.
    pub fn get() -> Option<Arc<OriginContext>> {
        GLOBAL_ORIGIN_CONTEXT.with_borrow(Clone::clone)
    }

    /// Gets the value current set for a given symbol on the
    /// active context.
    #[inline]
    pub fn get_value<T: Send + Sync + 'static>(
        symbol: &'static impl Symbol<Type = T>,
    ) -> Result<Option<Arc<T>>, Error> {
        GLOBAL_ORIGIN_CONTEXT.with_borrow(|maybe_ctx| {
            maybe_ctx.as_ref().map_or_else(
                || {
                    Err(make_err!(
                        Code::Internal,
                        "Expected active context to be set"
                    ))
                },
                |ctx| ctx.get_value(symbol),
            )
        })
    }

    /// Forks the active context, returning a new context with the same data.
    #[inline]
    pub fn fork() -> Result<OriginContext, Error> {
        GLOBAL_ORIGIN_CONTEXT.with_borrow(|maybe_ctx| {
            maybe_ctx.as_ref().map_or_else(
                || {
                    Err(make_err!(
                        Code::Internal,
                        "Expected active context to be set"
                    ))
                },
                |ctx| Ok(ctx.as_ref().clone()),
            )
        })
    }
}

thread_local! {
  /// Global context that is used to store the active context.
  static GLOBAL_ORIGIN_CONTEXT: RefCell<Option<Arc<OriginContext>>> = const { RefCell::new(None) };
}

/// Special guard struct that is used to hold the previous context and restore it
/// when the guard is released or dropped.
struct ContextDropGuard {
    prev_ctx: Option<Arc<OriginContext>>,
    new_ctx_ptr: *const OriginContext,
}

impl ContextDropGuard {
    /// Places the new context in the global context, stores the previous context
    /// and returns a new `ContextDropGuard`, so if it is ever released or dropped
    /// the previous context will be restored.
    #[inline]
    fn new(new_ctx: Arc<OriginContext>) -> Self {
        let new_ctx_ptr = Arc::as_ptr(&new_ctx);
        let prev_ctx = GLOBAL_ORIGIN_CONTEXT.replace(Some(new_ctx));
        Self {
            prev_ctx,
            new_ctx_ptr,
        }
    }

    /// Swap the global context with the previous context.
    /// Returns the context used in the `.enter()`/`.new()` call.
    fn restore_global_context(&mut self) -> Arc<OriginContext> {
        let new_ctx = GLOBAL_ORIGIN_CONTEXT
            .replace(self.prev_ctx.take())
            .expect("Expected global context to be set");
        assert_eq!(self.new_ctx_ptr, Arc::as_ptr(&new_ctx));
        new_ctx
    }

    /// Release the context guard and restore the previous context.
    /// This is an optimization, so we don't need to clone our Arc
    /// if the caller can use the context after releasing it.
    #[inline]
    fn release(mut self) -> Arc<OriginContext> {
        let new_ctx = self.restore_global_context();
        std::mem::forget(self); // Prevent the destructor from being called.
        new_ctx
    }
}

impl Drop for ContextDropGuard {
    #[inline]
    fn drop(&mut self) {
        // If the user calls `.release()` the drop() will not be triggered.
        // If a panic happens, the drop() will be called and the `.release()`
        // will not be called, this is our safety net.
        self.restore_global_context();
    }
}

pin_project! {
    #[must_use = "futures do nothing unless you `.await` or poll them"]
    pub struct ContextAwareFuture<F> {
        // `ManuallyDrop` is used so we can call `self.span.enter()` in the `drop()`
        // of our inner future, then drop the span.
        #[pin]
        inner: ManuallyDrop<Instrumented<F>>,
        context: Option<Arc<OriginContext>>,
    }

    impl <F> PinnedDrop for ContextAwareFuture<F> {
        #[inline]
        fn drop(this: Pin<&mut Self>) {
            let this = this.project();
            // Note: If the future panics, the context will not be restored, so
            // this is a best effort to provide access to our global context
            // in the destructors the event of a panic.
            let _enter = this.context.take().map(OriginContext::enter);
            // SAFETY: 1. `Pin::get_unchecked_mut()` is safe, because this isn't
            //             different from wrapping `T` in `Option` and calling
            //             `Pin::set(&mut this.inner, None)`, except avoiding
            //             additional memory overhead.
            //         2. `ManuallyDrop::drop()` is safe, because
            //            `PinnedDrop::drop()` is guaranteed to be called only
            //            once.
            unsafe {
                ManuallyDrop::drop(this.inner.get_unchecked_mut());
            }
        }
    }
}

impl<T> ContextAwareFuture<T> {
    /// Utility function to create a new `ContextAwareFuture` from the
    /// active context.
    #[must_use = "futures do nothing unless you `.await` or poll them"]
    #[inline]
    pub fn new_from_active(inner: Instrumented<T>) -> ContextAwareFuture<T> {
        if let Some(ctx) = ActiveOriginContext::get() {
            ContextAwareFuture::new(Some(ctx), inner)
        } else {
            // Useful to get tracing stack trace.
            tracing::error!("OriginContext must be set");
            panic!("OriginContext must be set");
        }
    }

    #[must_use = "futures do nothing unless you `.await` or poll them"]
    #[inline]
    pub(crate) const fn new(context: Option<Arc<OriginContext>>, inner: Instrumented<T>) -> Self {
        Self {
            inner: ManuallyDrop::new(inner),
            context,
        }
    }
}

impl<T: Future> Future for ContextAwareFuture<T> {
    type Output = T::Output;

    #[inline]
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();
        let Some(ctx) = this.context.take() else {
            // Useful to get tracing stack trace.
            tracing::error!("Expected context to be set");
            panic!("Expected context to be set");
        };
        let enter = ctx.enter();
        // Since `inner` is only moved when the future itself is dropped, `inner` will
        // never move, so this should be safe.
        // see: https://docs.rs/tracing/0.1.40/src/tracing/instrument.rs.html#297
        let inner = unsafe { this.inner.map_unchecked_mut(|v| &mut **v) };
        let result = inner.poll(cx);
        assert!(
            this.context.replace(enter.release()).is_none(),
            "Expected context to be unset"
        );
        result
    }
}
