# frozen_string_literal: true

require 'bindata'

module TSP
  class Packet < BinData::Record
    endian :little
    count_bytes_remaining :bytes_remaining

    bit4 :marker, :initial_value => 0xF
    bit28 :sequence
    bit32 :timestamp
    string :data, :read_length => -> { bytes_remaining - 10 }
    string :footer, :length => 2, :initial_value => "\r\n"
  end
end
