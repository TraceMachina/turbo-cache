#!/bin/bash

# Test script to check if CAS and AC configurations conflict

# Function to simulate the service configuration and run the check
check_store_conflict() {
    local cas_config="$1"
    local ac_config="$2"

    # Simulate the function to check store conflict
    if [[ "$cas_config" == "$ac_config" ]]; then
        echo "CAS and AC use the same store '$cas_config' in the config"
        return 1
    fi

    return 0
}

# Test case where CAS and AC use the same store
test_conflict_when_cas_and_ac_use_same_store() {
    local cas_store="store1"
    local ac_store="store1"

    check_store_conflict "$cas_store" "$ac_store"
    if [[ $? -eq 1 ]]; then
        echo "Test passed: Conflict detected when CAS and AC use the same store"
    else
        echo "Test failed: Conflict not detected when CAS and AC use the same store"
        exit 1
    fi
}

# Test case where CAS and AC use different stores
test_no_conflict_when_cas_and_ac_use_different_stores() {
    local cas_store="store1"
    local ac_store="store2"

    check_store_conflict "$cas_store" "$ac_store"
    if [[ $? -eq 0 ]]; then
        echo "Test passed: No conflict detected when CAS and AC use different stores"
    else
        echo "Test failed: Conflict detected when CAS and AC use different stores"
        exit 1
    fi
}

# Run the tests
test_conflict_when_cas_and_ac_use_same_store
test_no_conflict_when_cas_and_ac_use_different_stores

echo "All tests completed."