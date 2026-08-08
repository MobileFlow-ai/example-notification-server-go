RUNTIME_QA_COMPOSE = docker compose \
	-f runtime-qa/docker-compose.yml \
	-p xmtp-bridge-runtime-qa

.PHONY: runtime-qa runtime-qa-full runtime-qa-up runtime-qa-down runtime-qa-vectors

runtime-qa:
	./runtime-qa/run.sh

runtime-qa-full:
	RUNTIME_QA_INCLUDE_OPT_IN=1 ./runtime-qa/run.sh

runtime-qa-up:
	$(RUNTIME_QA_COMPOSE) up --build --detach --wait

runtime-qa-down:
	$(RUNTIME_QA_COMPOSE) down --volumes --remove-orphans

runtime-qa-vectors:
	@go run ./runtime-qa/cmd/gate6check \
		-cases runtime-qa/vectors/gate6.json
