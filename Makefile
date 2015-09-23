#
# Makefile for running unit tests
#
# List of subdirectories to build
TEST_FOLDER := ./test/
# List of unit test directories for libraries
UNITTESTS := $(sort $(dir $(wildcard $(TEST_FOLDER)*/unittest/*)))
TESTDIRS := $(UNITTESTS:%=build-%)
CLEANTESTDIRS := $(UNITTESTS:%=clean-%)
COVERAGEFILE := ./lcov/coverage.info

#
# Define compiler toolchain
#
include toolchain_rules.mk

$(eval $(call generate_rules,$(LIB),$(SRCS)))

# Extend default clean rule
clean: clean-extra

$(TESTDIRS):
	@yotta install --test-dependencies own
	@make -C $(@:build-%=%)

$(CLEANDIRS):
	@make -C $(@:clean-%=%) clean

$(CLEANTESTDIRS):
	@make -C $(@:clean-%=%) clean

.PHONY: test
test: $(TESTDIRS)
	@rm -rf ./lcov
	@mkdir -p lcov
	@mkdir -p lcov/results
	@find ./test -name '*.xml' | xargs cp -t ./lcov/results/
	@rm -f lcov/index.xml
	@./xsl_script.sh
	@cp junit_xsl.xslt lcov/.
	@xsltproc -o lcov/testresults.html lcov/junit_xsl.xslt lcov/index.xml
	@rm -f lcov/junit_xsl.xslt
	@rm -f lcov/index.xml
	@lcov -d test/. -c -o $(COVERAGEFILE)
	@lcov -q -r $(COVERAGEFILE) "/usr*" -o $(COVERAGEFILE)
	@lcov -q -r $(COVERAGEFILE) "/test*" -o $(COVERAGEFILE)
	@lcov -q -r $(COVERAGEFILE) "/mbed-client/*" -o $(COVERAGEFILE)
	@genhtml -q $(COVERAGEFILE) --show-details --output-directory lcov/html
	@echo mbed-client-mbed-os module unit tests built

clean-extra: $(CLEANDIRS) \
	$(CLEANTESTDIRS)
