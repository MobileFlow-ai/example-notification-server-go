# example-notification-server-go

Example push notification server, written in Golang

## Project status

![Status](https://camo.githubusercontent.com/47c9762c88d56b96ffa436e2af994dab07f6f61f2a0388cd08be7d42b1b8fef5/68747470733a2f2f696d672e736869656c64732e696f2f62616467652f50726f6a6563745f5374617475732d446576656c6f7065725f507265766965772d79656c6c6f77)

This project is ready to serve as a reference for you to start building.

Many applications will have different needs for push notifications (different delivery providers, different metadata attached to payloads, etc), and this repo is designed to be forked and customized for each application's needs.

## Prerequisites

1. Go 1.26
2. Docker and Docker Compose
3. Nix

## Local Setup

To start the XMTP service and database, run:

```sh
./dev/up
```

If `xnet-cli` is not already installed, `./dev/up` will try to install it with Nix.

You should then be able to build the server using:

```sh
./dev/build
```

## Usage

### Running the server

The server can be run using the `./dev/run` script. Both the `worker` (which
listens for XMTP messages and dispatches them to configured delivery services)
and the `api` service (which handles HTTP/GRPC requests) are optional. A worker
with zero delivery services is valid for audit-only operation. The current
Hytch candidate rejects APNS activation until the A9 and Gate 8 deployment
gates documented in
[`docs/railway-dev-runbook.md`](docs/railway-dev-runbook.md) are complete.

```sh
## Only has to be run once
./dev/up
./dev/start
```

### Command line options

To see a full list of command line options run

```sh
./dev/run --help
```

The generated help from the candidate binary is authoritative; it is not
duplicated here so that new safety and maintenance options cannot be hidden by
a stale snapshot.

### Generating code

If you have made a change to the files in the `proto` folder, you will need to regenerate the related Go code. You can do that with:

```sh
./dev/gen-proto
```

You must have the `Buf` CLI installed on your machine. Learn more [here](https://buf.build/docs/installation).

```sh
brew install bufbuild/buf/buf
```

To just rebuild the notification protos run:

```sh
buf generate
```

If you change the SQL in `pkg/db/sqlc`, regenerate the typed query package with:

```sh
./dev/gen-sqlc
```

### Creating migrations

To add a new database migration, run:

```sh
./dev/create-migration <name>
```

This creates paired `.up.sql` and `.down.sql` files in `pkg/db/migrations`.

### Migrating existing Bun databases

This repository now uses `golang-migrate` for schema tracking. Fresh databases run the embedded migrations normally. Existing Bun-initialized databases are detected on startup and reconciled onto the `golang-migrate` bookkeeping table without rebuilding the existing application tables.

If you need the exact Bun-to-`golang-migrate` handoff details, see `pkg/db/AGENTS.md` and `pkg/db/migrations/migrations.go`.

### Testing the API

The API supports plain JSON and can be used via CURL

```sh
./dev/run --api
curl \
    --header "Content-Type: application/json" \
    --data '{"installationId": "123", "deliveryMechanism": {"apnsDeviceToken": "foo"}}' \
    http://localhost:8080/notifications.v1.Notifications/RegisterInstallation
```

### Running the tests

Test files must be run serially right now, due to the shared database instance which is wiped after most tests.

```sh
go test -p 1 ./...
```

## Extending the server

The implementation of the `Delivery` service are designed to be easily extended. For a production application, you will likely want to replace them with a more robust set of tools for sending notifications idempotently. To do that, you would modify `cmd/server/main.go` and add a Delivery Service implementation.

If you are using Firebase for push delivery, the only modifications needed (if any) may be to customize the payload sent to clients.

## Deployment

You will need to deploy your own instance of the Notification Server, with the appropriate credentials to send push notifications on behalf of your app. The deployed service will require access to a Postgres database as well as the ability to connect to the public internet.

You may choose to run both the API and Listener in a single service or as two separate services, depending on the expected load to the API server. For high traffic applications it is recommended to run the API server and Listener as separate services.

## Implementing a client

Once you have the server deployed, you will need to connect to it from your client application to register devices and subscriptions. There is a guide to help guide you in this process [here](./docs/notifications-client-guide.md).
