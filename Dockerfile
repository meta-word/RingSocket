FROM archlinux:20200106

RUN pacman --noconfirm -Sy gcc git make && \
	echo "Installed required Arch Linux packages: gcc, git, and make."
RUN cd /opt && \
	git clone https://github.com/wbudd/jgrandson.git && \
	cd jgrandson && \
	make && \
	make install && \
	echo "Installed JSON library dependency: Jgrandson."
RUN cd /opt && \
	git clone https://github.com/wbudd/ringsocket.git && \
	cd ringsocket && \
	make && \
	make install && \
	echo "Installed RingSocket."
RUN pacman --noconfirm -S iproute2 python && \
	echo "Installed Ringsocket test suite dependencies: python3 and iproute2."
