import { initializeRedisClients } from './redis';
import { initializeProtobuf } from './protobuf';
import { handleEvent } from './eventHandler';
import { startWebSocket } from './websocket';
import { startWebServer } from './http';


export async function start() {
  // Google Remote Path
  const googleProtoPath = `https://raw.githubusercontent.com/googleapis/googleapis/1f2e5aab4f95b9bd38dd1ac8c7486657f93c1975/google/devtools/build/v1`;

  // Bazel Remote Path
  const bazelProtoPath = `https://raw.githubusercontent.com/bazelbuild/bazel/9.0.0-pre.20241023.1/src/main/java/com/google/devtools/build/lib/buildeventstream/proto`;

  // TODO(SchahinRohani): Add Buck2 Protos for future Buck2 support
  // const buck2ProtoPath = `https://raw.githubusercontent.com/facebook/buck2/2024-11-01/app/buck2_data/data.proto`;

  // Actual using Protos.
  const PublishBuildEventProto =`${googleProtoPath}/publish_build_event.proto`;
  const BazelBuildEventStreamProto = `${bazelProtoPath}/build_event_stream.proto`;

  const protos = [ PublishBuildEventProto, BazelBuildEventStreamProto ]

  console.info("Link to: \n")
  console.info("Google Publish Build Events Proto:\n", PublishBuildEventProto, "\n");
  console.info("Bazel Build Event Stream Proto:\n", BazelBuildEventStreamProto, "\n")

  // Load Remote Bazel Proto Files
  const protoTypes = await initializeProtobuf(protos)

  const { redisClient, commandClient } = await initializeRedisClients();

  // Subscribe to the build_event channel
  await redisClient.subscribe(process.env.NATIVELINK_PUB_SUB_CHANNEL || "build_event", async (message: string) => {
    await handleEvent(message, commandClient, protoTypes);
  });

  const websocketServer = startWebSocket();
  const webServer = startWebServer();

  process.on('SIGINT', async () => {
    await redisClient.disconnect();
    await commandClient.disconnect();
    console.info("Received SIGINT. Shutdown gracefully.")
    process.exit();
  });
  process.on('SIGTERM', async () => {
    await redisClient.disconnect();
    await commandClient.disconnect();
    console.info("Received SIGTERM. Shutdown gracefully.")
    process.exit();
  });
}
