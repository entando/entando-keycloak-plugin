OS := $(shell uname)

preview: 
ifeq ($(OS),Darwin)
	sed -i "" -e "s/version:.*/version: $(PREVIEW_VERSION)/" Chart.yaml
	sed -i "" -e "s/version:.*/version: $(PREVIEW_VERSION)/" ../*/Chart.yaml
	sed -i "" -e "s/tag:.*/tag: $(PREVIEW_VERSION)/" values.yaml
else ifeq ($(OS),Linux)
	sed -i -e "s/version:.*/version: $(PREVIEW_VERSION)/" Chart.yaml
	sed -i -e "s/version:.*/version: $(PREVIEW_VERSION)/" ../*/Chart.yaml
	sed -i -e "s|repository:.*|repository: $(DOCKER_REGISTRY)\/entando\/entando-sample-app-ekp|" values.yaml
	sed -i -e "s/tag:.*/tag: $(PREVIEW_VERSION)/" values.yaml
	sed -i -e "s/ENTANDO_DOCKER_REGISTRY_OVERRIDE:.*/ENTANDO_DOCKER_REGISTRY_OVERRIDE: $(DOCKER_REGISTRY)/" values.yaml
	sed -i -e "s/routingSuffix:.*/routingSuffix: $(ENTANDO_DEFAULT_ROUTING_SUFFIX)/" values.yaml
	sed -i -e "s/nameSuffix:.*/nameSuffix: $(PIPELINE_CODE)pr$(PULL_NUMBER)/" values.yaml
else
	echo "platfrom $(OS) not supported to release from"
	exit -1
endif
	echo "  version: $(PREVIEW_VERSION)" >> requirements.yaml
	jx step helm build
