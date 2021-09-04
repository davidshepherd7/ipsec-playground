
## Start the system
.PHONY: start
start: strongswan ubuntu-with-tools
	docker-compose up --remove-orphans

## Connect to the containers
.PHONY: moon
moon:
	docker exec -it ipsec-playground_moon_1 bash
.PHONY: alice
alice:
	docker exec -it ipsec-playground_alice_1 bash
.PHONY: sun
sun:
	docker exec -it ipsec-playground_sun_1 bash
.PHONY: bob
bob:
	docker exec -it ipsec-playground_bob_1 bash


## Build the containers
.PHONY: strongswan
strongswan:
	docker build --tag strongswan ./strongswan/

.PHONY: ubuntu-with-tools
ubuntu-with-tools:
	docker build --tag ubuntu-with-tools ./ubuntu-with-tools/
