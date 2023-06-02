# test_spiderfootdb.py
import pytest
import unittest

from spiderfoot import SpiderFootDb, SpiderFootEvent


@pytest.mark.usefixtures
class TestSpiderFootDb(unittest.TestCase):
    """
    Test SpiderFootDb
    """

    def test_init_argument_opts_with_empty_value_should_raise_ValueError(self):
        """
        Test __init__(self, opts, init=False)
        """
        with self.assertRaises(ValueError):
            SpiderFootDb(dict())

    def test_init_argument_opts_with_empty_key___database_value_should_raise_ValueError(self):
        """
        Test __init__(self, opts, init=False)
        """
        with self.assertRaises(ValueError):
            opts = dict()
            opts['__database'] = None
            SpiderFootDb(opts)

    def test_init_should_create_SpiderFootDb_object(self):
        """
        Test __init__(self, opts, init=False)
        """
        sfdb = SpiderFootDb(self.default_options, False)
        self.assertIsInstance(sfdb, SpiderFootDb)

    @unittest.skip("todo")
    def test_create_should_create_database_schema(self):
        """
        Test create(self)
        """
        sfdb = SpiderFootDb(self.default_options, False)
        sfdb.create()
        self.assertEqual('TBD', 'TBD')

    def test_close_should_close_database_connection(self):
        """
        Test close(self)
        """
        sfdb = SpiderFootDb(self.default_options, False)
        sfdb.close()

    def test_search_should_return_a_list(self):
        """
        Test search(self, criteria, filterFp=False)
        """
        sfdb = SpiderFootDb(self.default_options, False)

        criteria = {
            'scan_id': "example scan id",
            'type': "example type",
            'value': "example value",
            'regex': "example regex"
        }

        search_results = sfdb.search(criteria, False)
        self.assertIsInstance(search_results, list)
        self.assertFalse(search_results)

    def test_search_argument_criteria_key_of_invalid_type_should_raise_TypeError(self):
        """
        Test search(self, criteria, filterFp=False)
        """
        sfdb = SpiderFootDb(self.default_options, False)

        criteria = {
            'type': "example type",
            'value': "example value",
            'regex': []
        }

        with self.assertRaises(TypeError):
            sfdb.search(criteria, False)

    def test_search_argument_criteria_no_valid_criteria_should_raise_ValueError(self):
        """
        Test search(self, criteria, filterFp=False)
        """
        sfdb = SpiderFootDb(self.default_options, False)

        criteria = {
            'invalid_criteria': "example invalid criteria"
        }

        with self.assertRaises(ValueError):
            sfdb.search(criteria, False)

    def test_search_argument_criteria_one_criteria_should_raise_ValueError(self):
        """
        Test search(self, criteria, filterFp=False)
        """
        sfdb = SpiderFootDb(self.default_options, False)

        criteria = {
            'type': "example type"
        }

        with self.assertRaises(ValueError):
            sfdb.search(criteria, False)

    def test_eventTypes_should_return_a_list(self):
        """
        Test eventTypes(self)
        """
        sfdb = SpiderFootDb(self.default_options, False)
        sfdb.eventTypes()

    def test_scanLogEvent_should_create_a_scan_log_event(self):
        """
        Test scanLogEvent(self, instanceId, classification, message, component=None)
        """
        sfdb = SpiderFootDb(self.default_options, False)
        sfdb.scanLogEvent("", "", "", None)

        self.assertEqual('TBD', 'TBD')

    @unittest.skip("todo")
    def test_scanInstanceCreate_should_create_a_scan_instance(self):
        """
        Test scanInstanceCreate(self, instanceId, scanName, scanTarget)
        """
        sfdb = SpiderFootDb(self.default_options, False)

        instance_id = "example instance id"
        scan_name = "example scan name"
        scan_target = "example scan target"

        sfdb.scanInstanceCreate(instance_id, scan_name, scan_target)

        self.assertEqual('TBD', 'TBD')

    @unittest.skip("todo")
    def test_scanInstanceCreate_argument_instanceId_already_exists_should_halt_and_catch_fire(self):
        """
        Test scanInstanceCreate(self, instanceId, scanName, scanTarget)
        """
        sfdb = SpiderFootDb(self.default_options, False)

        instance_id = "example instance id"
        scan_name = "example scan name"
        scan_target = "example scan target"

        sfdb.scanInstanceCreate(instance_id, scan_name, scan_target)

        instance_id = "example instance id"
        scan_name = "example scan name"
        scan_target = "example scan target"

        with self.assertRaises(IOError):
            sfdb.scanInstanceCreate(instance_id, scan_name, scan_target)

        self.assertEqual('TBD', 'TBD')

    def test_scanInstanceSet(self):
        """
        Test scanInstanceSet(self, instanceId, started=None, ended=None, status=None)
        """
        sfdb = SpiderFootDb(self.default_options, init=True)

        scan_instance = 'example scan instance'
        sfdb.scanInstanceSet(scan_instance, None, None, None)
        self.assertEqual('TBD', 'TBD')

    def test_scanInstanceGet_should_return_scan_info(self):
        """
        Test scanInstanceGet(self, instanceId)
        """
        sfdb = SpiderFootDb(self.default_options, False)

        instance_id = "example instance id"
        scan_name = "example scan name"
        scan_target = "example scan target"

        sfdb.scanInstanceCreate(instance_id, scan_name, scan_target)

        scan_instance_get = sfdb.scanInstanceGet(instance_id)

        self.assertEqual(len(scan_instance_get), 6)

        self.assertIsInstance(scan_instance_get[0], str)
        self.assertEqual(scan_instance_get[0], scan_name)

        self.assertIsInstance(scan_instance_get[1], str)
        self.assertEqual(scan_instance_get[1], scan_target)

        self.assertIsInstance(scan_instance_get[2], float)

        self.assertIsInstance(scan_instance_get[3], float)

        self.assertIsInstance(scan_instance_get[4], float)

        self.assertIsInstance(scan_instance_get[5], str)
        self.assertEqual(scan_instance_get[5], 'CREATED')

    def test_scanResultSummary_should_return_a_list(self):
        """
        Test scanResultSummary(self, instanceId, by="type")
        """
        sfdb = SpiderFootDb(self.default_options, False)

        instance_id = "example instance id"
        scan_results_summary = sfdb.scanResultSummary(instance_id, "type")
        self.assertIsInstance(scan_results_summary, list)

    def test_scanResultSummary_argument_by_of_invalid_type_should_raise_TypeError(self):
        """
        Test scanResultSummary(self, instanceId, by="type")
        """
        sfdb = SpiderFootDb(self.default_options, False)

        instance_id = "example instance id"
        # invalid_types = [None, list(), dict(), int()]
        # for invalid_type in invalid_types:
        #     with self.subTest(invalid_type=invalid_type):
        #         with self.assertRaises(TypeError):
        #             sfdb.scanResultSummary(instance_id, invalid_type)

        with self.assertRaises(ValueError):
            sfdb.scanResultSummary(instance_id, "invalid filter type")

    def test_scanResultSummary_argument_by_invalid_value_should_raise_ValueError(self):
        """
        Test scanResultSummary(self, instanceId, by="type")
        """
        sfdb = SpiderFootDb(self.default_options, False)

        instance_id = "example instance id"
        with self.assertRaises(ValueError):
            sfdb.scanResultSummary(instance_id, "invalid filter type")

    def test_scanResultEvent_should_return_a_list(self):
        """
        Test scanResultEvent(self, instanceId, eventType='ALL', filterFp=False)
        """
        sfdb = SpiderFootDb(self.default_options, False)

        instance_id = "example instance id"
        scan_result_event = sfdb.scanResultEvent(instance_id, "", False)
        self.assertIsInstance(scan_result_event, list)

    def test_scanResultEventUnique_should_return_a_list(self):
        """
        Test scanResultEventUnique(self, instanceId, eventType='ALL', filterFp=False)
        """
        sfdb = SpiderFootDb(self.default_options, False)

        instance_id = "example instance id"
        scan_result_event = sfdb.scanResultEventUnique(instance_id, "", False)
        self.assertIsInstance(scan_result_event, list)

    def test_scanLogs_should_return_a_list(self):
        """
        Test scanLogs(self, instanceId, limit=None, fromRowId=None, reverse=False)
        """
        sfdb = SpiderFootDb(self.default_options, False)

        instance_id = "example instance id"
        scan_logs = sfdb.scanLogs(instance_id, None, None, None)
        self.assertIsInstance(scan_logs, list)

        self.assertEqual('TBD', 'TBD')

    def test_scanErrors_should_return_a_list(self):
        """
        Test scanErrors(self, instanceId, limit=None)
        """
        sfdb = SpiderFootDb(self.default_options, False)
        instance_id = "example instance id"
        scan_instance = sfdb.scanErrors(instance_id)
        self.assertIsInstance(scan_instance, list)

    def test_scanInstanceDelete(self):
        """
        Test scanInstanceDelete(self, instanceId)
        """
        sfdb = SpiderFootDb(self.default_options, False)
        instance_id = "example instance id"
        sfdb.scanInstanceDelete(instance_id)

        self.assertEqual('TBD', 'TBD')

    @unittest.skip("todo")
    def test_scanResultsUpdateFP(self):
        """
        Test scanResultsUpdateFP(self, instanceId, resultHashes, fpFlag)
        """
        sfdb = SpiderFootDb(self.default_options, False)

        instance_id = "example instance id"
        scan_name = "example scan name"
        scan_target = "example scan target"

        sfdb.scanInstanceCreate(instance_id, scan_name, scan_target)

        result_hashes = None
        fp_flag = None
        sfdb.scanResultsUpdateFP(instance_id, result_hashes, fp_flag)

        self.assertEqual('TBD', 'TBD')

    def test_configSet_should_set_config_opts(self):
        """
        Test configSet(self, optMap=dict())
        """
        sfdb = SpiderFootDb(self.default_options, False)
        opts = dict()
        opts['example'] = 'example non-default config opt'
        sfdb.configSet(opts)

        config = sfdb.configGet()
        self.assertIsInstance(config, dict)
        self.assertIn('example', config)

        self.assertEqual('TBD', 'TBD')

    def test_configGet_should_return_a_dict(self):
        """
        Test configGet(self)
        """
        sfdb = SpiderFootDb(self.default_options, False)
        config = sfdb.configGet()
        self.assertIsInstance(config, dict)

    def test_configClear_should_clear_config(self):
        """
        Test configClear(self)
        """
        sfdb = SpiderFootDb(self.default_options, False)

        opts = dict()
        opts['example'] = 'example non-default config opt'
        sfdb.configSet(opts)

        config = sfdb.configGet()
        self.assertIsInstance(config, dict)
        self.assertIn('example', config)

        sfdb.configClear()

        config = sfdb.configGet()
        self.assertIsInstance(config, dict)
        self.assertNotIn('example', config)

    def test_scanConfigSet_argument_instanceId_with_empty_value_should_raise_ValueError(self):
        """
        Test scanConfigSet(self, id, optMap=dict())
        """
        sfdb = SpiderFootDb(self.default_options, False)

        with self.assertRaises(ValueError):
            sfdb.scanConfigSet("", dict())

    def test_scanConfigGet_should_return_a_dict(self):
        """
        Test scanConfigGet(self, instanceId)
        """
        sfdb = SpiderFootDb(self.default_options, False)

        instance_id = "example instance id"
        scan_config = sfdb.scanConfigGet(instance_id)
        self.assertIsInstance(scan_config, dict)

    def test_scanEventStore_should_store_a_scan_event(self):
        """
        Test scanEventStore(self, instanceId, sfEvent, truncateSize=0)
        """
        sfdb = SpiderFootDb(self.default_options, False)

        event_type = 'ROOT'
        event_data = 'example data'
        module = ''
        source_event = ''
        event = SpiderFootEvent(event_type, event_data, module, source_event)
        instance_id = "example instance id"
        sfdb.scanEventStore(instance_id, event)

    def test_scanEventStore_argument_instanceId_with_empty_value_should_raise_ValueError(self):
        """
        Test scanEventStore(self, instanceId, sfEvent, truncateSize=0)
        """
        sfdb = SpiderFootDb(self.default_options, False)

        event = ""
        with self.assertRaises(ValueError):
            sfdb.scanEventStore("", event)

    def test_scanEventStore_argument_sfEvent_with_empty_eventType_property_value_should_raise_ValueError(self):
        """
        Test scanEventStore(self, instanceId, sfEvent, truncateSize=0)
        """
        sfdb = SpiderFootDb(self.default_options, False)

        event_type = 'ROOT'
        event_data = 'example data'
        module = ''
        source_event = ''
        source_event = SpiderFootEvent(event_type, event_data, module, source_event)

        event_type = 'example event type'
        event_data = 'example event data'
        module = 'example module'
        event = SpiderFootEvent(event_type, event_data, module, source_event)

        instance_id = "example instance id"

        with self.assertRaises(ValueError):
            event.eventType = ''
            sfdb.scanEventStore(instance_id, event)

    def test_scanEventStore_argument_sfEvent_with_empty_data_property_value_should_raise_ValueError(self):
        """
        Test scanEventStore(self, instanceId, sfEvent, truncateSize=0)
        """
        sfdb = SpiderFootDb(self.default_options, False)

        event_type = 'ROOT'
        event_data = 'example data'
        module = ''
        source_event = ''
        source_event = SpiderFootEvent(event_type, event_data, module, source_event)

        event_type = 'example event type'
        event_data = 'example event data'
        module = 'example module'
        event = SpiderFootEvent(event_type, event_data, module, source_event)

        instance_id = "example instance id"

        with self.assertRaises(ValueError):
            event.data = ''
            sfdb.scanEventStore(instance_id, event)

    def test_scanEventStore_argument_sfEvent_with_empty_module_property_value_should_raise_ValueError(self):
        """
        Test scanEventStore(self, instanceId, sfEvent, truncateSize=0)
        """
        sfdb = SpiderFootDb(self.default_options, False)

        event_type = 'ROOT'
        event_data = 'example data'
        module = ''
        source_event = ''
        source_event = SpiderFootEvent(event_type, event_data, module, source_event)

        event_type = 'example event type'
        event_data = 'example event data'
        module = 'example module'
        event = SpiderFootEvent(event_type, event_data, module, source_event)

        instance_id = "example instance id"
        with self.assertRaises(ValueError):
            event.module = ''
            sfdb.scanEventStore(instance_id, event)

    def test_scanEventStore_argument_sfEvent_with_empty_confidence_property_value_should_raise_ValueError(self):
        """
        Test scanEventStore(self, instanceId, sfEvent, truncateSize=0)
        """
        sfdb = SpiderFootDb(self.default_options, False)

        event_type = 'ROOT'
        event_data = 'example data'
        module = ''
        source_event = ''
        source_event = SpiderFootEvent(event_type, event_data, module, source_event)

        event_type = 'example event type'
        event_data = 'example event data'
        module = 'example module'
        event = SpiderFootEvent(event_type, event_data, module, source_event)

        instance_id = "example instance id"
        invalid_values = [-1, 101]
        for invalid_value in invalid_values:
            with self.subTest(invalid_value=invalid_value):
                with self.assertRaises(ValueError):
                    event = SpiderFootEvent(event_type, event_data, module, source_event)
                    event.confidence = invalid_value
                    sfdb.scanEventStore(instance_id, event)

    def test_scanEventStore_argument_sfEvent_with_empty_visibility_property_value_should_raise_ValueError(self):
        """
        Test scanEventStore(self, instanceId, sfEvent, truncateSize=0)
        """
        sfdb = SpiderFootDb(self.default_options, False)

        event_type = 'ROOT'
        event_data = 'example data'
        module = ''
        source_event = ''
        source_event = SpiderFootEvent(event_type, event_data, module, source_event)

        event_type = 'example event type'
        event_data = 'example event data'
        module = 'example module'
        event = SpiderFootEvent(event_type, event_data, module, source_event)

        instance_id = "example instance id"
        invalid_values = [-1, 101]
        for invalid_value in invalid_values:
            with self.subTest(invalid_value=invalid_value):
                with self.assertRaises(ValueError):
                    event = SpiderFootEvent(event_type, event_data, module, source_event)
                    event.visibility = invalid_value
                    sfdb.scanEventStore(instance_id, event)

    def test_scanEventStore_argument_sfEvent_with_empty_risk_property_value_should_raise_ValueError(self):
        """
        Test scanEventStore(self, instanceId, sfEvent, truncateSize=0)
        """
        sfdb = SpiderFootDb(self.default_options, False)

        event_type = 'ROOT'
        event_data = 'example data'
        module = ''
        source_event = ''
        source_event = SpiderFootEvent(event_type, event_data, module, source_event)

        event_type = 'example event type'
        event_data = 'example event data'
        module = 'example module'
        event = SpiderFootEvent(event_type, event_data, module, source_event)

        instance_id = "example instance id"
        invalid_values = [-1, 101]
        for invalid_value in invalid_values:
            with self.subTest(invalid_value=invalid_value):
                with self.assertRaises(ValueError):
                    event = SpiderFootEvent(event_type, event_data, module, source_event)
                    event.risk = invalid_value
                    sfdb.scanEventStore(instance_id, event)

    def test_scanInstanceList_should_return_a_list(self):
        """
        Test scanInstanceList(self)
        """
        sfdb = SpiderFootDb(self.default_options, False)

        scan_instances = sfdb.scanInstanceList()
        self.assertIsInstance(scan_instances, list)

    def test_scanResultHistory_should_return_a_list(self):
        """
        Test scanResultHistory(self, instanceId)
        """
        sfdb = SpiderFootDb(self.default_options, False)

        instance_id = "example instance id"
        scan_result_history = sfdb.scanResultHistory(instance_id)
        self.assertIsInstance(scan_result_history, list)

    def test_scanElementSourcesDirect_should_return_a_list(self):
        """
        Test scanElementSourcesDirect(self, instanceId, elementIdList)
        """
        sfdb = SpiderFootDb(self.default_options, False)

        instance_id = "example instance id"
        element_id_list = []
        scan_element_sources_direct = sfdb.scanElementSourcesDirect(instance_id, element_id_list)
        self.assertIsInstance(scan_element_sources_direct, list)

        self.assertEqual('TBD', 'TBD')

    def test_scanElementChildrenDirect_should_return_a_list(self):
        """
        Test scanElementChildrenDirect(self, instanceId, elementIdList)
        """
        sfdb = SpiderFootDb(self.default_options, False)

        instance_id = "example instance id"
        scan_element_children_direct = sfdb.scanElementChildrenDirect(instance_id, list())
        self.assertIsInstance(scan_element_children_direct, list)

        self.assertEqual('TBD', 'TBD')

    def test_scanElementSourcesAll_should_return_a_list(self):
        """
        Test scanElementSourcesAll(self, instanceId, childData)
        """
        sfdb = SpiderFootDb(self.default_options, False)

        instance_id = "example instance id"
        child_data = ["example child", "example child"]
        scan_element_sources_all = sfdb.scanElementSourcesAll(instance_id, child_data)
        self.assertIsInstance(scan_element_sources_all, list)

        self.assertEqual('TBD', 'TBD')

    def test_scanElementSourcesAll_argument_childData_with_empty_value_should_raise_ValueError(self):
        """
        Test scanElementSourcesAll(self, instanceId, childData)
        """
        sfdb = SpiderFootDb(self.default_options, False)

        instance_id = "example instance id"
        child_data = []

        with self.assertRaises(ValueError):
            sfdb.scanElementSourcesAll(instance_id, child_data)

    def test_scanElementChildrenAll_should_return_a_list(self):
        """
        Test scanElementChildrenAll(self, instanceId, parentIds)
        """
        sfdb = SpiderFootDb(self.default_options, False)

        instance_id = "example instance id"
        scan_element_children_all = sfdb.scanElementChildrenAll(instance_id, list())
        self.assertIsInstance(scan_element_children_all, list)

        self.assertEqual('TBD', 'TBD')
