RUNTIME_QA_COMPOSE = docker compose \
	-f runtime-qa/docker-compose.yml \
	-p xmtp-bridge-runtime-qa
A9_PROVISIONING_QA_IMAGE ?= xmtp-bridge-a9-provisioning-qa:local

.PHONY: a9-provisioning-qa runtime-qa runtime-qa-full runtime-qa-up runtime-qa-down runtime-qa-vectors

a9-provisioning-qa:
	docker build --tag "$(A9_PROVISIONING_QA_IMAGE)" .
	./scripts/tests/a9-entrypoint-container-test.sh "$(A9_PROVISIONING_QA_IMAGE)"

runtime-qa: a9-provisioning-qa
	./runtime-qa/run.sh

runtime-qa-full: a9-provisioning-qa
	RUNTIME_QA_INCLUDE_OPT_IN=1 ./runtime-qa/run.sh

runtime-qa-up:
	$(RUNTIME_QA_COMPOSE) up --build --detach --wait

runtime-qa-down:
	$(RUNTIME_QA_COMPOSE) down --volumes --remove-orphans

runtime-qa-vectors:
	@go run ./runtime-qa/cmd/gate6check \
		-cases runtime-qa/vectors/gate6.json
