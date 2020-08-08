
all:
	make -C src

src/include/config.h: kconfig.yaml
	./scripts/config/config.py genconfig

defconfig:
	./scripts/config/config.py defconfig

checkconfig: kconfig.yaml
	./scripts/config/config.py checkconfig

genconfig: src/include/config.h

clean:
	make -C src clean

distclean: clean
	-rm -f src/include/config.h kconfig.yaml
