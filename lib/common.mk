AM_CFLAGS = $(WERROR_CFLAGS) $(WSTACK_CFLAGS) $(WARN_CFLAGS) $(NETTLE_CFLAGS) $(P11_KIT_CFLAGS) \
	$(CODE_COVERAGE_CFLAGS)
COMMON_LDFLAGS = $(CODE_COVERAGE_CFLAGS)
