PCAP_CFLAGS=$(shell pcap-config --cflags --libs)

all: dump-classifier udp_tai

dump-classifier: dump-classifier.c
	${CC} ${CFLAGS} $(PCAP_CFLAGS) -o $@ $<

udp_tai: udp_tai.c
	${CC} ${CFLAGS} -lpthread -o $@ $<

clean:
	@rm dump-classifier
	@rm udp_tai

.PHONY: clean debug
