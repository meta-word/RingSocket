#!/bin/sh

# Make sure the current directory is the directory containing this script.
SCRIPT_PATH=${0%/*}
if [ "$0" != "$SCRIPT_PATH" ] && [ "$SCRIPT_PATH" != "" ]
then
    cd $SCRIPT_PATH
fi

if [ "$(pgrep ringsocket)" != "" ]
then
	echo "Existing RingSocket instance(s) detected: killing all with \"sudo killall ringsocket\" to free up resources."
	sudo killall ringsocket
	sleep 1
	if [ "$(pgrep ringsocket)" != "" ]
	then
		echo "Failed to kill existing RingSocket instance(s). Exiting."
		exit 1
	fi
fi

make || exit 1

# Generate a random TCP port to list on in order to avoid triggering EADDRINUSE
# errors that may occur when RingSocket calls bind() after a previous instance
# of RingSocket on the same port was recently terminated (which is an
# unavoidable consequence of TCP_WAIT states being mandated by the TCP protocol,
# and enforced by the Linux kernel network stack).
RANDOM_PORT=$(shuf -i 1024-65535 -n 1)
echo "Configuring random TCP listen port $RANDOM_PORT."

# Use the iproute2 "ss" utility to check that the port isn't already in use.
while [ "$(ss -HOant | grep -cP :$RANDOM_PORT\\D)" != "0" ]
do
	echo "TCP port $RANDOM_PORT appears to be already in use."
	RANDOM_PORT=$(shuf -i 1024-65535 -n 1)
	echo "Trying random TCP port $RANDOM_PORT instead."
done

# Use the "sed" utility to replace RANDOM_PORT_PLACEHOLDERs.
sed "s/RANDOM_PORT_PLACEHOLDER/$RANDOM_PORT/g" rs_test.json > /tmp/rs_test.json
sed "s/RANDOM_PORT_PLACEHOLDER/$RANDOM_PORT/" rs_test_client.html > /tmp/rs.html

cp *.so /tmp/ || exit 1

if [ "$1" == "--preload" ]
then
	echo "Launching RingSocket: \"sudo LD_PRELOAD=/tmp/rs_preload_sham_io.so ringsocket /tmp/rs_test.json\""
	sudo LD_PRELOAD=/tmp/rs_preload_sham_io.so ringsocket /tmp/rs_test.json
else
	echo "Launching RingSocket: \"sudo ringsocket /tmp/rs_test.json\""
	sudo ringsocket /tmp/rs_test.json
fi

echo ""
echo "Please open (or reload) file:///tmp/rs.html in a browser to interactively spawn any number of test client connections."

echo ""
echo "To shut the current RingSocket instance down, issue \"sudo killall ringsocket\" (or run this script again)."
