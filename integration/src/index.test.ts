import Koa from "koa";
import { bodyParser } from "@koa/bodyparser";
import type { Client as XmtpClient } from "@xmtp/node-sdk";
import { expect, test, afterAll, describe } from "vitest";
import { createNotificationClient, randomClient, sleep } from ".";
import type { NotificationResponse } from "./types";

const PORT = 7777;

describe("notifications", () => {
  const pendingResolvers = new Map<
    string,
    (body: NotificationResponse) => void
  >();
  const pendingNotifications = new Map<string, NotificationResponse[]>();

  // Set up a Koa server to receive messages from the HttpDelivery service
  const app = new Koa();
  app.use(bodyParser());
  app.use(async (ctx) => {
    const body = ctx.request.body as NotificationResponse;
    const installationId = body.installation?.id;
    if (!installationId) {
      console.log("Notification missing installation id");
      ctx.status = 200;
      return;
    }

    const resolver = pendingResolvers.get(installationId);
    if (resolver) {
      pendingResolvers.delete(installationId);
      resolver(body);
    } else {
      const queue = pendingNotifications.get(installationId) ?? [];
      queue.push(body);
      pendingNotifications.set(installationId, queue);
    }
    ctx.status = 200;
  });
  const server = app.listen(PORT);

  afterAll(() => {
    server.close();
  });

  const waitForNotification = (
    installationId: string,
    timeoutMs: number,
  ): Promise<NotificationResponse> =>
    new Promise((resolve, reject) => {
      const queued = pendingNotifications.get(installationId);
      if (queued && queued.length > 0) {
        const [nextNotification, ...rest] = queued;
        if (rest.length > 0) {
          pendingNotifications.set(installationId, rest);
        } else {
          pendingNotifications.delete(installationId);
        }
        resolve(nextNotification);
        return;
      }

      const timer = setTimeout(() => {
        pendingResolvers.delete(installationId);
        reject(
          new Error(`Timed out waiting for notification for ${installationId}`),
        );
      }, timeoutMs);

      pendingResolvers.set(installationId, (body) => {
        clearTimeout(timer);
        resolve(body);
      });
    });

  const expectNoNotification = async (
    installationId: string,
    timeoutMs: number,
  ) => {
    const timedOut = await waitForNotification(installationId, timeoutMs).then(
      () => false,
      (error: unknown) => {
        if (error instanceof Error && error.message === `Timed out waiting for notification for ${installationId}`) {
          return true;
        }
        throw error;
      },
    );
    expect(timedOut).toBe(true);
  };

  const waitForConversationCount = async (
    client: XmtpClient<any>,
    expectedCount: number,
    timeoutMs: number,
  ) => {
    const start = Date.now();
    let lastError: unknown;

    while (Date.now() - start < timeoutMs) {
      try {
        await client.conversations.syncAll();
      } catch (error) {
        lastError = error;
      }

      const conversations = await client.conversations.list();
      if (conversations.length >= expectedCount) {
        return conversations;
      }

      await new Promise((resolve) => setTimeout(resolve, 250));
    }

    if (lastError) {
      throw lastError;
    }

    throw new Error(`Timed out waiting for ${expectedCount} conversations`);
  };

  test("conversation invites", async () => {
    const alix = await randomClient();
    const bo = await randomClient();

    const alixNotificationClient = createNotificationClient();
    await alixNotificationClient.registerInstallation({
      installationId: alix.installationId,
      deliveryMechanism: {
        deliveryMechanismType: {
          value: "token",
          case: "apnsDeviceToken",
        },
      },
    });

    const alixWelcomeTopic = `/xmtp/mls/1/w-${alix.installationId}/proto`;
    await alixNotificationClient.subscribeWithMetadata({
      installationId: alix.installationId,
      subscriptions: [
        {
          topic: alixWelcomeTopic,
          isSilent: true,
        },
      ],
    });

    // A plaintext welcome subscription cannot authorize a pre-decryption push.
    // Confirm the invite reached Alix through XMTP before checking the webhook.
    const boDm = await bo.conversations.createDm(alix.inboxId);
    const alixConversations = await waitForConversationCount(alix, 1, 15000);
    expect(alixConversations.some((c) => c.id === boDm.id)).toBe(true);
    await expectNoNotification(alix.installationId, 5000);
  });

  test("hmac keys", async () => {
    const alix = await randomClient();
    const bo = await randomClient();

    const alixNotificationClient = createNotificationClient();
    await alixNotificationClient.registerInstallation({
      installationId: alix.installationId,
      deliveryMechanism: {
        deliveryMechanismType: {
          value: "token",
          case: "apnsDeviceToken",
        },
      },
    });

    const boGroup = await bo.conversations.createGroup([alix.inboxId]);

    expect((await alix.conversations.list()).length).toEqual(0);
    const alixGroups = await waitForConversationCount(alix, 1, 15000);
    expect(alixGroups.length).toEqual(1);
    const alixGroup = alixGroups[0];

    const epochDurationMs = 30 * 24 * 60 * 60 * 1000;
    const earliestEpoch = Math.floor(Date.now() / epochDurationMs);
    const hmacKeys = alix.conversations.hmacKeys();
    const latestEpoch = Math.floor(Date.now() / epochDurationMs);
    expect(Object.keys(hmacKeys).length).toEqual(1);
    const conversationHmacKeys = hmacKeys[alixGroup.id];
    expect(conversationHmacKeys.length).toEqual(3);
    expect(conversationHmacKeys.every((v) => v.key.byteLength === 42)).toBe(true);
    const epochs = conversationHmacKeys.map((v) => Number(v.epoch)).sort((a, b) => a - b);
    expect(epochs[1]).toBeGreaterThanOrEqual(earliestEpoch);
    expect(epochs[1]).toBeLessThanOrEqual(latestEpoch);
    expect(epochs).toEqual([epochs[1] - 1, epochs[1], epochs[1] + 1]);

    const matchingKeys = conversationHmacKeys.map((v) => ({
      thirtyDayPeriodsSinceEpoch: Number(v.epoch),
      key: Uint8Array.from(v.key),
    }));
    const topic = alixGroup.topic;
    await alixNotificationClient.subscribeWithMetadata({
      installationId: alix.installationId,
      subscriptions: [
        {
          topic,
          isSilent: false,
          hmacKeys: matchingKeys,
        },
      ],
    });

    const notificationPromise = waitForNotification(alix.installationId, 15000);
    await alixGroup.sendText("This should never be delivered");
    await boGroup.sendText("This should be delivered");

    const notification = await notificationPromise;

    expect(notification.idempotency_key).toBeTypeOf("string");
    expect(notification.message.content_topic).toEqual(topic);
    expect(notification.message.message).toBeTypeOf("string");
    expect(notification.subscription.is_silent).toBe(false);
    expect(notification.installation.id).toEqual(alix.installationId);
    expect(notification.installation.delivery_mechanism.token === "token").toBe(true);
  });

  test("selective unsubscribe", async () => {
    const alix = await randomClient();
    const bo = await randomClient();
    const notifClient = createNotificationClient();

    // Register alix
    await notifClient.registerInstallation({
      installationId: alix.installationId,
      deliveryMechanism: {
        deliveryMechanismType: { value: "token", case: "apnsDeviceToken" },
      },
    });

    // Bo creates two groups with alix
    const group1 = await bo.conversations.createGroup([alix.inboxId]);
    const group2 = await bo.conversations.createGroup([alix.inboxId]);
    const alixGroups = await waitForConversationCount(alix, 2, 15000);

    // Subscribe to both group topics with HMAC keys
    const hmacKeys = alix.conversations.hmacKeys();
    await notifClient.subscribeWithMetadata({
      installationId: alix.installationId,
      subscriptions: alixGroups.map((g) => ({
        topic: g.topic,
        isSilent: false,
        hmacKeys: hmacKeys[g.id]?.map((v) => ({
          thirtyDayPeriodsSinceEpoch: Number(v.epoch),
          key: Uint8Array.from(v.key),
        })),
      })),
    });

    // Unsubscribe from group1 while keeping group2 active
    await notifClient.unsubscribe({
      installationId: alix.installationId,
      topics: [group1.topic],
    });

    // Send messages to both groups — only group2 should be delivered
    const notificationPromise = waitForNotification(alix.installationId, 15000);
    await group1.sendText("Should NOT be delivered");
    await group2.sendText("Should be delivered");

    const notification = await notificationPromise;
    expect(notification.message.content_topic).toEqual(group2.topic);
    await expectNoNotification(alix.installationId, 3000);
  });

  test("group self-message suppression", async () => {
    const alix = await randomClient();
    const bo = await randomClient();
    const notifClient = createNotificationClient();

    // Register alix
    await notifClient.registerInstallation({
      installationId: alix.installationId,
      deliveryMechanism: {
        deliveryMechanismType: { value: "token", case: "apnsDeviceToken" },
      },
    });

    // Bo creates group, invites alix
    const boGroup = await bo.conversations.createGroup([alix.inboxId]);
    const alixGroups = await waitForConversationCount(alix, 1, 15000);
    const alixGroup = alixGroups[0];

    // Alix subscribes with HMAC keys
    const hmacKeys = alix.conversations.hmacKeys();
    await notifClient.subscribeWithMetadata({
      installationId: alix.installationId,
      subscriptions: [
        {
          topic: alixGroup.topic,
          isSilent: false,
          hmacKeys: hmacKeys[alixGroup.id]?.map((v) => ({
            thirtyDayPeriodsSinceEpoch: Number(v.epoch),
            key: Uint8Array.from(v.key),
          })),
        },
      ],
    });

    // Both send messages — only bo's should be delivered
    await alixGroup.sendText("From alix — should NOT be delivered");
    await expectNoNotification(alix.installationId, 3000);
    const notificationPromise = waitForNotification(alix.installationId, 15000);
    await boGroup.sendText("From bo — should be delivered");

    const notification = await notificationPromise;
    expect(notification.message.content_topic).toEqual(alixGroup.topic);
    expect(notification.idempotency_key).toBeTypeOf("string");
    await expectNoNotification(alix.installationId, 3000);
  });

  test("unregister stops notifications", async () => {
    const alix = await randomClient();
    const bo = await randomClient();
    const notifClient = createNotificationClient();

    await notifClient.registerInstallation({
      installationId: alix.installationId,
      deliveryMechanism: {
        deliveryMechanismType: { value: "token", case: "apnsDeviceToken" },
      },
    });
    const boGroup = await bo.conversations.createGroup([alix.inboxId]);
    const [alixGroup] = await waitForConversationCount(alix, 1, 15000);
    const hmacKeys = alix.conversations.hmacKeys()[alixGroup.id];
    await notifClient.subscribeWithMetadata({
      installationId: alix.installationId,
      subscriptions: [{
        topic: alixGroup.topic,
        isSilent: false,
        hmacKeys: hmacKeys.map((v) => ({
          thirtyDayPeriodsSinceEpoch: Number(v.epoch),
          key: Uint8Array.from(v.key),
        })),
      }],
    });

    await boGroup.sendText("Before unregister");
    const before = await waitForNotification(alix.installationId, 15000);
    expect(before.message.content_topic).toEqual(alixGroup.topic);

    await notifClient.deleteInstallation({ installationId: alix.installationId });
    const afterId = await boGroup.sendText("After unregister");
    await expect.poll(async () => {
      await alixGroup.sync();
      return (await alixGroup.messages()).some((m) => m.id === afterId);
    }, { timeout: 10000 }).toBe(true);
    await expectNoNotification(alix.installationId, 5000);
  });
});
