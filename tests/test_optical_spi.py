import unittest
from analysis_scripts.optical_spi import (
    adapter_config,adapter_result,delay_argument,hardware_config,poll_round,scheduler_delay_argument,spi_source_rate,
)


class OpticalSpiTest(unittest.TestCase):
    def test_source_clock_selection_uses_separate_bus_fields(self):
        a=(3<<21)|(1<<24); b=(4<<21)|(2<<24)
        self.assertEqual(spi_source_rate(0,0),48000000)
        self.assertEqual(spi_source_rate(0,1<<12),48000000)
        self.assertEqual(spi_source_rate(0,(2<<12)|(3<<14),pll_b=b),128000000)
        self.assertEqual(spi_source_rate(1,(2<<12)|(3<<14),pll_a=a),256000000)
        with self.assertRaises(ValueError): spi_source_rate(2,0)

    def test_probe_and_adapter_mask_collapses_modes(self):
        self.assertEqual(adapter_config(8000000,0x801),dict(frequency=8000000,low_control_bits=0,width_field=8))
        for flags in range(8):
            self.assertEqual(adapter_config(1,flags)['low_control_bits'],3 if flags in (2,3,4,5,6,7) else 0)

    def test_register_word_preserves_only_reviewed_high_bits(self):
        result=hardware_config(48000000,8000000,0x801,0xffffffff)
        self.assertEqual(result,dict(control=0x100c,configuration=0xff870002,enable_mask=0x18d))
        self.assertEqual(hardware_config(48000000,8000000,6,0,1)['control'],0x1007)

    def test_divider_floor_zero_request_and_high_requested_rate(self):
        self.assertEqual(hardware_config(48000000,10000000,0,0)['configuration'],0x70001)
        self.assertEqual(hardware_config(48000000,0,0,0)['configuration'],0x70000)
        self.assertEqual(hardware_config(48000000,48000000,0,0)['configuration'],0x70001)
        self.assertEqual(hardware_config(48000000,96000000,0,0)['configuration'],0x70000)

    def test_poll_busy_and_separate_tx_rx_status_inputs(self):
        self.assertEqual(poll_round(2,2,(4,2,0x10),0,1000),dict(tx_remaining=2,rx_remaining=2,outcome='continue'))
        self.assertEqual(poll_round(2,2,(0,2,0),0,1000),dict(tx_remaining=1,rx_remaining=2,outcome='continue'))
        self.assertEqual(poll_round(2,2,(0,0,0x10),0,1000),dict(tx_remaining=2,rx_remaining=1,outcome='continue'))

    def test_timeout_is_strict_and_can_follow_final_byte(self):
        self.assertEqual(poll_round(1,1,(0,2,0x10),1000,1000),dict(tx_remaining=0,rx_remaining=0,outcome='continue'))
        self.assertEqual(poll_round(1,1,(0,2,0x10),1001,1000),dict(tx_remaining=0,rx_remaining=0,outcome='timeout'))
        self.assertEqual(poll_round(0,0,(0,0,0),2**64-1,0)['outcome'],'complete_at_entry')

    def test_adapter_error_collapses_native_codes(self):
        self.assertEqual(adapter_result(0),0)
        for value in (1,2,3,0xffffffff): self.assertEqual(adapter_result(value),2)

    def test_cycle_delay_argument_wrap_and_scheduler_clamp(self):
        self.assertEqual(delay_argument(7),7000)
        self.assertEqual(delay_argument(0xffffffff),0xfffffc18)
        for value in (0,10,0x418937,0xffffffff): self.assertEqual(scheduler_delay_argument(value),value)
        for value in (0x418938,0x418939,0xfffffffe): self.assertEqual(scheduler_delay_argument(value),0x418937)

    def test_invalid_bounded_inputs(self):
        for args in ((-1,1,(0,0,0),0,1),(4097,1,(0,0,0),0,1),(1,1,(0,0),0,1),(1,1,(0,True,0),0,1)):
            with self.assertRaises(ValueError): poll_round(*args)
        for value in (-1,2**32,True,1.0):
            for function in (delay_argument,scheduler_delay_argument,adapter_result):
                with self.assertRaises(ValueError): function(value)


if __name__ == '__main__': unittest.main()
