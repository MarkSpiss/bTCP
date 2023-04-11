# Mark Špīss s1024217
# Lien Wullink s1005601

import struct
import logging
from enum import IntEnum
from btcp.constants import *


logger = logging.getLogger(__name__)


class BTCPStates(IntEnum):
    """Enum class that helps you implement the bTCP state machine.

    Don't use the integer values of this enum directly. Always refer to them as
    BTCPStates.CLOSED etc.

    These states are NOT exhaustive! We left out at least one state that you
    will need to implement the bTCP state machine correctly. The intention of
    this enum is to give you some idea for states and how simple the
    transitions between them are.

    Feel free to implement your state machine in a different way, without
    using such an enum.
    """
    CLOSED      = 0
    ACCEPTING   = 1
    SYN_SENT    = 2
    SYN_RCVD    = 3
    ESTABLISHED = 4 # There's an obvious state that goes here. Give it a name.
    FIN_SENT    = 5
    CLOSING     = 6
    __          = 7 # If you need more states, extend the Enum like this.


class BTCPSignals(IntEnum):
    """Enum class that you can use to signal from the Application thread
    to the Network thread.

    For example, rather than explicitly change state in the Application thread,
    you could put one of these in a variable that the network thread reads the
    next time it ticks, and handles the state change in the network thread.
    """
    ACCEPT = 1
    CONNECT = 2
    SHUTDOWN = 3


class BTCPSocket:
    """Base class for bTCP client and server sockets. Contains static helper
    methods that will definitely be useful for both sending and receiving side.
    """
    def __init__(self, window, timeout):
        logger.debug("__init__ called")
        self._window = window
        self._timeout = timeout
        self._state = BTCPStates.CLOSED
        logger.debug("Socket initialized with window %i and timeout %i",
                     self._window, self._timeout)

    @staticmethod
    def build_segment_header(seqnum, acknum,
                             syn_set=False, ack_set=False, fin_set=False,
                             window=0x01, length=0, checksum=0):
        """Pack the method arguments into a valid bTCP header using struct.pack

        This method is given because historically students had a lot of trouble
        figuring out how to pack and unpack values into / out of the header.
        We have *not* provided an implementation of the corresponding unpack
        method (see below), so inspect the code, look at the documentation for
        struct.pack, and figure out what this does, so you can implement the
        unpack method yourself.

        Of course, you are free to implement it differently, as long as you
        do so correctly *and respect the network byte order*.

        You are allowed to change the SYN, ACK, and FIN flag locations in the
        flags byte, but make sure to do so correctly everywhere you pack and
        unpack them.

        The method is written to have sane defaults for the arguments, so
        you don't have to always set all flags explicitly true/false, or give
        a checksum of 0 when creating the header for checksum computation.
        """
        logger.debug("build_segment_header() called")
        flag_byte = syn_set << 2 | ack_set << 1 | fin_set
        logger.debug("build_segment_header() done")
        return struct.pack("!HHBBHH",
                           seqnum, acknum, flag_byte, window, length, checksum)


    @staticmethod
    def unpack_segment_header(header):
        """Unpack the individual bTCP header field values from the header.

        Remember that Python supports multiple return values through automatic
        tupling, so it's easy to simply return all of them in one go rather
        than make a separate method for every individual field.
        """


        logger.debug("unpack_segment_header() called")
        bundled_flags = header[4]
        flag_s = (bundled_flags & 0x04) >> 2
        flag_a = (bundled_flags & 0x02) >> 1
        flag_f = (bundled_flags & 0x01)
        

        seq_num, ack_num, _, window_size, data_length, checksum = struct.unpack("!HHBBHH", header)

        logger.debug("unpack_segment_header() done")
        return seq_num, ack_num, flag_s, flag_a, flag_f, window_size, data_length, checksum
    
    @staticmethod
    def in_cksum(segment):
        """Compute the internet checksum of the segment given as argument.
        Consult lecture 3 for details.

        Our bTCP implementation always has an even number of bytes in a segment.

        Remember that, when computing the checksum value before *sending* the
        segment, the checksum field in the header should be set to 0x0000, and
        then the resulting checksum should be put in its place.
        """
        logger.debug("in_cksum() called")

        segment_header = segment[:10]
        _, _, _, _, _, _, _, checksum = BTCPSocket.unpack_segment_header(segment_header)

        wordsum = 0x0000

        for word in struct.iter_unpack("!H", segment):
            wordsum += word[0]

        if(wordsum > 0xffff):
            carry = (wordsum & 0xF0000) >> 16
            wordsum_uncarried = wordsum & 0x0FFFF
            wordsum = wordsum_uncarried + carry
        
            if(wordsum != 0xFFFF):
                checksum = ~wordsum & 0xFFFF
            else:
                checksum = wordsum

        return checksum

    @staticmethod
    def verify_checksum(segment):
        """Verify that the checksum indicates is an uncorrupted segment.

        Mind that you change *what* signals that to the correct value(s).
        """
        logger.debug("verify_cksum() called")
        segment_header = segment[:HEADER_SIZE]
        

        # 1) Extract the checksum
        seq_num, ack_num, flag_s, flag_a, flag_f, window_size, data_length, extracted_checksum = BTCPSocket.unpack_segment_header(segment_header)

        # 2) Set checksum field to 0x0000 and recompute the checksum
        # (the checksum is located in Bytes 8,9 of segment)
        header_zero_checksum = BTCPSocket.build_segment_header(seq_num, ack_num, syn_set=flag_s, ack_set=flag_a, fin_set=flag_f, window=window_size, length=data_length, checksum=0)
        segment_data = segment[HEADER_SIZE:PAYLOAD_SIZE]

        zero_segment = header_zero_checksum + segment_data

        recomputed_checksum = BTCPSocket.in_cksum(zero_segment)

        # 3) Compare
        logger.debug("verify_cksum() done")
        return recomputed_checksum == extracted_checksum

    # Computes the checksum of a given segment (should initially be 0) and sets the computed value
    # for checksum field
    @staticmethod
    def compute_and_set_checksum(segment):
        checksum = BTCPSocket.in_cksum(segment)
        checksum_bytes = struct.pack("!H", checksum)
        segment_list = list(segment)
        segment_list[8:HEADER_SIZE] = checksum_bytes
        segment_bytes = bytearray(segment_list)
        return segment_bytes

    @staticmethod
    def seq_num_increment(seq_num):
        if seq_num == MAX_SEQ_NUM:
            seq_num = 0
        else:
            seq_num += 1
        return seq_num
