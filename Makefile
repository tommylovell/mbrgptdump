TEMPFILES = *.o *.out
PROGS = mbrgptdump

all:
	gcc -o ${PROGS} ${PROGS}.c
	sudo chown root:root ${PROGS}
	sudo chmod u+s       ${PROGS}
	if [ ! -e ~/bin ]; then mkdir ~/bin/; fi
	sudo mv ${PROGS} ~/bin/${PROGS}

clean:
	-rm -f ${PROGS} ${TEMPFILES}
	-rm -f ~/bin/${PROGS}
