# Copyright 2020-present Open Networking Foundation
# SPDX-License-Identifier: Apache-2.0

# Absolute directory of this Makefile
DIR := $(patsubst %/,%,$(dir $(abspath $(lastword $(MAKEFILE_LIST)))))
DIR_SHA := $(shell echo -n "$(DIR)" | shasum | cut -c1-7)
UID := $(shell id -u)

# .env cannot be included as-is as some variables are defined with ${A:-B}
# notation to allow overrides. Resolve overrides in a temp file and include that.
RESOLVED_ENV := /tmp/basic-tna.$(DIR_SHA).env
IGNORE := $(shell bash -c 'eval "source $(DIR)/.env && echo \"$$(cat $(DIR)/.env)\""' > $(RESOLVED_ENV))
include $(RESOLVED_ENV)

# Replace dots with underscores
SDE_VER_ := $(shell echo $(SDE_VERSION) | tr . _)

# By default use docker volume for the mvn artifacts cache, but allow passing a
# local ~/.m2 directory using the MVN_CACHE env.
MVN_CACHE_DOCKER_VOLUME := mvn-cache-$(DIR_SHA)
MVN_CACHE ?= $(MVN_CACHE_DOCKER_VOLUME)
# By default use the maven settings in local ~/.m2, but allow passing a custom
# settings.
MVN_SETTINGS ?= $(shell test -f ~/.m2/settings.xml && echo "$${HOME}/.m2/settings.xml")
MVN_FLAGS ?= 

ONOS_HOST ?= localhost
ONOS_URL ?= http://$(ONOS_HOST):8181/onos
ONOS_UTIL_URL ?=http://$(ONOS_HOST):8188/api
ONOS_CURL := curl --fail -sSL --user onos:rocks --noproxy localhost

PIPECONF_APP_NAME := org.stratumproject.basic-tna
PIPECONF_OAR_FILE := $(DIR)/target/basic-tna-1.0.1-SNAPSHOT.oar

# Profiles to build by default (all)
PROFILES ?= basic

export SHOW_SENSITIVE_OUTPUT ?= true

deps:
	docker pull $(SDE_TM_DOCKER_IMG)
	docker pull $(SDE_P4C_DOCKER_IMG)
	docker pull $(STRATUM_DOCKER_IMG)
	docker pull $(STRATUM_BMV2_IMG)
	docker pull $(TESTER_DOCKER_IMG)
	docker pull $(PIPELINE_CONFIG_BUILDER_IMG)
	docker pull $(MAVEN_DOCKER_IMAGE)

build: clean $(PROFILES) pipeconf

all: $(PROFILES)

basic: basic-v1model basic-tna

basic-tna:
	@$(DIR)/p4src/tna/build.sh basic ""

basic-v1model:
	@${DIR}/p4src/v1model/build.sh basic ""

#remove the second
constants:
	docker run -v $(DIR):$(DIR) -w $(DIR) --rm --user $(UID) \
		--entrypoint ./util/gen-p4-constants.py $(TESTER_DOCKER_IMG) \
		-o $(DIR)/src/main/java/org/stratumproject/basic/tna/behaviour/P4InfoConstants.java \
		p4info $(DIR)/p4src/tna/build/basic/sde_$(SDE_VER_)/p4info.txt
	docker run -v $(DIR):$(DIR) -w $(DIR) --rm \
		--user $(UID) \
		$(SDE_P4C_DOCKER_IMG) \
		get-hdr-size.py --py-out "$(DIR)/ptf/tests/common/bmd_bytes.py" "$(DIR)/p4src/tna/build"

_m2_vol:
	docker volume create --opt o=uid=$(UID) --opt device=tmpfs --opt type=tmpfs $(MVN_CACHE_DOCKER_VOLUME)
ifneq ($(MVN_SETTINGS),)
	$(eval MVN_SETTINGS_MOUNT := -v $(MVN_SETTINGS):/.m2/settings.xml)
endif

_mvn_package: _m2_vol
	$(info *** Building ONOS app...)
	@mkdir -p target
	docker run --dns 8.8.8.8 --rm -v $(DIR):/mvn-src -w /mvn-src --user $(UID) \
		-e MAVEN_OPTS=-Dmaven.repo.local=/.m2 \
		-e MAVEN_CONFIG=/.m2 \
		-v /root/.m2:/.m2 \
		$(MVN_SETTINGS_MOUNT) $(MAVEN_DOCKER_IMAGE) mvn $(MVN_FLAGS) clean package

pipeconf: _mvn_package
	$(info *** ONOS pipeconf .oar package created succesfully)
	@ls -1 $(DIR)/target/*.oar
_pipeconf-oar-exists:
	@test -f $(PIPECONF_OAR_FILE) || (echo "pipeconf .oar not found" && exit 1)

pipeconf-install: _pipeconf-oar-exists
	$(info *** Installing and activating pipeconf app in ONOS at $(ONOS_HOST)...)
	$(ONOS_CURL) -X POST -H Content-Type:application/octet-stream \
		$(ONOS_URL)/v1/applications?activate=true \
		--data-binary @$(PIPECONF_OAR_FILE)
	@echo

pipeconf-uninstall:
	$(info *** Uninstalling pipeconf app from ONOS at $(ONOS_HOST)...)
	-$(ONOS_CURL) -X DELETE $(ONOS_URL)/v1/applications/$(PIPECONF_APP_NAME)
	@echo

netcfg-tofino:
	$(info *** Pushing tofino-netcfg.json to ONOS at $(ONOS_HOST)...)
	$(ONOS_CURL) -X POST -H Content-Type:application/json \
		$(ONOS_UTIL_URL)/topo -d@./tofino.json
	@echo

netcfg-bmv2:
	$(info *** Pushing tofino-netcfg.json to ONOS at $(ONOS_HOST)...)
	$(ONOS_CURL) -X POST -H Content-Type:application/json \
		$(ONOS_UTIL_URL)/topo -d@./domain1-5-7-new-oar.json
	@echo

netcfg-satellite:
	$(info *** Pushing tofino-netcfg.json to ONOS at $(ONOS_HOST)...)
	$(ONOS_CURL) -X POST -H Content-Type:application/json \
		$(ONOS_UTIL_URL)/topo -d@./domain3-satellite.json
	@echo

netcfg-domain1:
	$(info *** Pushing tofino-netcfg.json to ONOS at $(ONOS_HOST)...)
	$(ONOS_CURL) -X POST -H Content-Type:application/json \
		$(ONOS_UTIL_URL)/topo -d@./domain1_netcfg.json
	@echo

netcfg-domain5:
	$(info *** Pushing tofino-netcfg.json to ONOS at $(ONOS_HOST)...)
	$(ONOS_CURL) -X POST -H Content-Type:application/json \
		$(ONOS_UTIL_URL)/topo -d@./domain5_netcfg.json
	@echo

netcfg-domain7:
	$(info *** Pushing tofino-netcfg.json to ONOS at $(ONOS_HOST)...)
	$(ONOS_CURL) -X POST -H Content-Type:application/json \
		$(ONOS_UTIL_URL)/topo -d@./domain7_netcfg.json
	@echo
p4i:
	$(info *** Started p4i app at http://localhost:3000)
	docker run -d --rm --name p4i -v$(DIR):$(DIR)/p4src/tna/build -w $(DIR)/p4src/tna/build -p 3000:3000/tcp --init --cap-add CAP_SYS_ADMIN --cap-add CAP_NET_ADMIN $(SDE_P4I_DOCKER_IMG) xvfb-run /opt/p4i/p4i

p4i-stop:
	docker kill p4i

#remove
reuse-lint:
	docker run --rm -v $(DIR):/basic-tna -w /basic-tna omecproject/reuse-verify:latest reuse lint

env:
	@cat $(RESOLVED_ENV) | grep -v "#"

format:
	.github/format.sh

build-tester-img:
	DOCKER_BUILDKIT=1 docker build -f ptf/Dockerfile --build-arg=BUILDKIT_INLINE_CACHE=1 \
 		--cache-from "${TESTER_DOCKER_IMG}" -t "${TESTER_DOCKER_IMG}" .

push-tester-img:
	docker push "${TESTER_DOCKER_IMG}"

clean:
	-rm -rf src/main/resources/p4c-out
	-rm -rf p4src/tna/build
	-rm -rf p4src/v1model/build
	-rm -rf target

deep-clean: clean
	-docker volume rm $(MVN_CACHE_DOCKER_VOLUME) > /dev/null 2>&1

onos-cli:
	$(info *** Connecting to the ONOS CLI... password: rocks)
	$(info *** Top exit press Ctrl-D)
	@ssh -o "UserKnownHostsFile=/dev/null" -o "StrictHostKeyChecking=no" -o LogLevel=ERROR -p 8101 onos@localhost

