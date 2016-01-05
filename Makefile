# wrapper to run waf

WAF=./waf

all:
	$(WAF) build

install:
	$(WAF) install

uninstall:
	$(WAF) uninstall

clean:
	$(WAF) clean
