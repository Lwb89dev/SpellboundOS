import unittest
from analysis_scripts.spi_ownership import (
    chip_select_store,completion_plan,reference_step,register_output,register_request,transfer_plan,
)


class SpiOwnershipTest(unittest.TestCase):
    def test_poll_lifetime_and_operation_error_release(self):
        trace=['mutex_take','select','poll_operation','deselect','mutex_release']
        self.assertEqual(transfer_plan(),dict(result=0,trace=trace,release_deferred=False))
        self.assertEqual(transfer_plan(operation_result=2),dict(result=-14,trace=trace,release_deferred=False))

    def test_failed_chip_selection_still_releases(self):
        self.assertEqual(transfer_plan(take_result=2),dict(result=-14,
            trace=['mutex_take','select','deselect','mutex_release'],release_deferred=False))

    def test_mutex_and_release_failures_do_not_change_selected_result(self):
        self.assertEqual(transfer_plan(mutex_result=0xfffffffe),transfer_plan())
        self.assertEqual(transfer_plan(release_result=2),transfer_plan())

    def test_missing_tables_or_operations_return_without_bus_take(self):
        for kwargs in (dict(table_present=False),dict(operation_present=False),dict(dma=True,operation_present=False)):
            self.assertEqual(transfer_plan(**kwargs),dict(result=0,trace=[],release_deferred=False))

    def test_missing_chip_select_callbacks_keep_mutex_lifetime(self):
        self.assertEqual(transfer_plan(cs_present=False)['trace'],['mutex_take','poll_operation','mutex_release'])

    def test_dma_success_defers_release_and_error_releases_now(self):
        self.assertEqual(transfer_plan(dma=True),dict(result=0,
            trace=['mutex_take','select','dma_operation'],release_deferred=True))
        self.assertEqual(transfer_plan(dma=True,operation_result=2),dict(result=-14,
            trace=['mutex_take','select','dma_operation','deselect','mutex_release'],release_deferred=False))

    def test_completion_releases_before_user_callback(self):
        self.assertEqual(completion_plan(dma_now=True),dict(result=0,trace=['deselect','mutex_release','user_callback']))
        self.assertEqual(completion_plan(dma_now=True,user_callback=False),dict(result=0,trace=['deselect','mutex_release']))
        self.assertEqual(completion_plan(dma_now=True,cs_present=False),dict(result=0,trace=['mutex_release','user_callback']))

    def test_completion_uses_current_flag_and_has_no_pending_latch(self):
        self.assertEqual(completion_plan(dma_now=False),dict(result=0,trace=['user_callback']))
        first=completion_plan(dma_now=True)
        self.assertEqual(completion_plan(dma_now=True),first)

    def test_enable_calls_for_each_nonzero_count_and_wraps(self):
        self.assertEqual(reference_step(0,enable=True),dict(count=1,invoke_callback=True))
        self.assertEqual(reference_step(1,enable=True),dict(count=2,invoke_callback=True))
        self.assertEqual(reference_step(65535,enable=True),dict(count=0,invoke_callback=False))

    def test_disable_at_zero_calls_again_without_underflow(self):
        for count in (0,1):self.assertEqual(reference_step(count,enable=False),dict(count=0,invoke_callback=True))
        self.assertEqual(reference_step(2,enable=False),dict(count=1,invoke_callback=False))
        self.assertEqual(reference_step(0,enable=False,callback_present=False),dict(count=0,invoke_callback=False))

    def test_chip_select_uses_separate_gpio_store_offsets(self):
        self.assertEqual(chip_select_store(0x91003000,0x200,selected=True),dict(address=0x91003014,value=0x200))
        self.assertEqual(chip_select_store(0x91003000,0x200,selected=False),dict(address=0x91003010,value=0x200))

    def test_optical_register_buffers(self):
        self.assertEqual(register_request(255),bytes.fromhex('ff8000'))
        self.assertEqual(register_request(9,value=171),bytes.fromhex('0900ab'))
        with self.assertRaises(ValueError):register_request(256)

    def test_failed_read_preserves_output_even_with_a_complete_buffer(self):
        self.assertEqual(register_output(0,b'\x11\x22\x46',165),70)
        self.assertEqual(register_output(0xfffffff2,b'\x11\x22\x46',165),165)
        with self.assertRaises(ValueError):register_output(0,b'\x46',165)

    def test_no_operation_success_copies_initial_dummy_byte(self):
        self.assertEqual(register_output(transfer_plan(operation_present=False)['result'],register_request(255),165),0)

    def test_invalid_status_selectors_reference_counts_and_address(self):
        for kwargs in (dict(dma=1),dict(mutex_result=-1),dict(take_result=True)):
            with self.assertRaises(ValueError):transfer_plan(**kwargs)
        for count in (-1,65536,True):
            with self.assertRaises(ValueError):reference_step(count,enable=True)
        with self.assertRaises(ValueError):chip_select_store(0xffffffff,1,selected=True)


if __name__=='__main__':unittest.main()
