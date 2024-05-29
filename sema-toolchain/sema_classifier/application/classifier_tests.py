import unittest
import sys

sys.path.insert(0, '/sema-classifier/application/')

from ClassifierApp import get_args, parse_class_args
from helper.ArgumentParserClassifier import ArgumentParserClassifier

class TestClassifier(unittest.TestCase):

    def test_REST_classifier_args(self):
        classifier_args = get_args()
        expected_result = [{'operation_mode':
                [{'name': 'classification', 'help': 'By malware family', 'type': 'bool', 'default': False, 'is_mutually_exclusive': True},
                {'name': 'detection', 'help': 'Cleanware vs Malware', 'type': 'bool', 'default': False, 'is_mutually_exclusive': True}],
            'classifier_used':
                [{'name': 'wl', 'help': 'TODO', 'type': 'bool', 'default': False, 'is_mutually_exclusive': True},
                {'name': 'inria', 'help': 'TODO', 'type': 'bool', 'default': False, 'is_mutually_exclusive': True},
                {'name': 'dl', 'help': 'TODO', 'type': 'bool', 'default': False, 'is_mutually_exclusive': True},
                {'name': 'gspan', 'help': 'TODO', 'type': 'bool', 'default': False, 'is_mutually_exclusive': True}],
            'Global classifiers parameters':
                [{'name': 'threshold', 'help': 'Threshold used for the classifier [0..1] (default : 0.45)', 'type': "<class 'float'>", 'default': 0.45, 'is_mutually_exclusive': False}]},
            {'Gspan options':
                [{'name': 'biggest_subgraph', 'help': 'Biggest subgraph consider for Gspan (default: 5)', 'type': "<class 'int'>", 'default': 5, 'is_mutually_exclusive': False},
                {'name': 'support', 'help': 'Support used for the gpsan classifier [0..1] (default : 0.75)', 'type': "<class 'float'>", 'default': 0.75, 'is_mutually_exclusive': False},
                {'name': 'ctimeout', 'help': 'Timeout for gspan classifier (default : 3sec)', 'type': "<class 'int'>", 'default': 3, 'is_mutually_exclusive': False}],
            'Deep Learning options':
                [{'name': 'epoch', 'help': 'Only for deep learning model: number of epoch (default: 5)\n Always 1 for FL model', 'type': "<class 'int'>", 'default': 5, 'is_mutually_exclusive': False},
                {'name': 'sepoch', 'help': 'Only for deep learning model: starting epoch (default: 1)\n', 'type': "<class 'int'>", 'default': 1, 'is_mutually_exclusive': False},
                {'name': 'data_scale', 'help': 'Only for deep learning model: data scale value (default: 0.9)', 'type': "<class 'float'>", 'default': 0.9, 'is_mutually_exclusive': False},
                {'name': 'vector_size', 'help': 'Only for deep learning model: Size of the vector used (default: 4)', 'type': "<class 'int'>", 'default': 4, 'is_mutually_exclusive': False},
                {'name': 'batch_size', 'help': 'Only for deep learning model: Batch size for the model (default: 1)', 'type': "<class 'int'>", 'default': 1, 'is_mutually_exclusive': False}],
            'Malware familly':
                [{'name': 'bancteian', 'help': None, 'type': 'bool', 'default': True, 'is_mutually_exclusive': False},
                {'name': 'delf', 'help': None, 'type': 'bool', 'default': True, 'is_mutually_exclusive': False},
                {'name': 'FeakerStealer', 'help': None, 'type': 'bool', 'default': True, 'is_mutually_exclusive': False},
                {'name': 'gandcrab', 'help': None, 'type': 'bool', 'default': True, 'is_mutually_exclusive': False},
                {'name': 'ircbot', 'help': None, 'type': 'bool', 'default': True, 'is_mutually_exclusive': False},
                {'name': 'lamer', 'help': None, 'type': 'bool', 'default': True, 'is_mutually_exclusive': False},
                {'name': 'nitol', 'help': None, 'type': 'bool', 'default': True, 'is_mutually_exclusive': False},
                {'name': 'RedLineStealer', 'help': None, 'type': 'bool', 'default': True, 'is_mutually_exclusive': False},
                {'name': 'sfone', 'help': None, 'type': 'bool', 'default': True, 'is_mutually_exclusive': False},
                {'name': 'sillyp2p', 'help': None, 'type': 'bool', 'default': True, 'is_mutually_exclusive': False},
                {'name': 'simbot', 'help': None, 'type': 'bool', 'default': True, 'is_mutually_exclusive': False},
                {'name': 'Sodinokibi', 'help': None, 'type': 'bool', 'default': True, 'is_mutually_exclusive': False},
                {'name': 'sytro', 'help': None, 'type': 'bool', 'default': True, 'is_mutually_exclusive': False},
                {'name': 'upatre', 'help': None, 'type': 'bool', 'default': True, 'is_mutually_exclusive': False},
                {'name': 'wabot', 'help': None, 'type': 'bool', 'default': True, 'is_mutually_exclusive': False},
                {'name': 'RemcosRAT', 'help': None, 'type': 'bool', 'default': True, 'is_mutually_exclusive': False}]},
            {'Global parameter':
                [{'name': 'verbose_classifier', 'help': 'Verbose output during train/classification  (default : False)', 'type': 'bool', 'default': False, 'is_mutually_exclusive': False},
                {'name': 'train', 'help': 'Launch training process, else classify/detect new sample with previously computed model', 'type': 'bool', 'default': False, 'is_mutually_exclusive': False},
                {'name': 'nthread', 'help': 'Number of thread used (default: max)', 'type': "<class 'int'>", 'default': 4, 'is_mutually_exclusive': False},
                {'name': 'binary_signatures', 'help': "Name of the folder containing binary'signatures to analyze", 'type': 'None', 'default': None, 'is_mutually_exclusive': False}]}]
        self.assertEqual(expected_result, classifier_args)


    def test_REST_classifier_parse_args(self):
        web_app_input = {'class_enable': 'class_enable', 'threshold': '0.5', 'classifier_used': 'wl',
                'operation_mode': 'classification', 'epoch': '5', 'sepoch': '1', 'data_scale': '1',
                'vector_size': '4', 'batch_size': '1', 'biggest_subgraph': '5', 'support': '0.75', 'ctimeout': '3',
                'bancteian': 'bancteian', 'delf': 'delf', 'FeakerStealer': 'FeakerStealer', 'gandcrab': 'gandcrab',
                'ircbot': 'ircbot', 'lamer': 'lamer', 'nitol': 'nitol', 'RedLineStealer': 'RedLineStealer', 'sfone': 'sfone',
                'sillyp2p': 'sillyp2p', 'simbot': 'simbot', 'Sodinokibi': 'Sodinokibi', 'sytro': 'sytro', 'upatre': 'upatre',
                'wabot': 'wabot', 'RemcosRAT': 'RemcosRAT', 'verbose_classifier': 'verbose_classifier', 'nthread': '6', 'binary_signatures': 'None'}
        parser = ArgumentParserClassifier()
        args_parser = parser.parser
        class_args, exp_args = parse_class_args(web_app_input, args_parser)
        expected_class_args = {'classification': True, 'wl': True, 'threshold': '0.5', 'biggest_subgraph': '5',
            'support': '0.75', 'ctimeout': '3', 'epoch': '5', 'sepoch': '1', 'data_scale': '1', 'vector_size': '4',
            'batch_size': '1', 'bancteian': True, 'delf': True, 'FeakerStealer': True, 'gandcrab': True, 'ircbot': True,
            'lamer': True, 'nitol': True, 'RedLineStealer': True, 'sfone': True, 'sillyp2p': True, 'simbot': True, 'Sodinokibi': True,
            'sytro': True, 'upatre': True, 'wabot': True, 'RemcosRAT': True, 'verbose_classifier': True, 'nthread': '6', 'binary_signatures': 'None'}
        expected_exp_args = ['--classification', '--wl', '--threshold', '0.5', '--biggest_subgraph', '5',
            '--support', '0.75', '--ctimeout', '3', '--epoch', '5', '--sepoch', '1', '--data_scale', '1',
            '--vector_size', '4', '--batch_size', '1', '--bancteian', '--delf', '--FeakerStealer', '--gandcrab',
            '--ircbot', '--lamer', '--nitol', '--RedLineStealer', '--sfone', '--sillyp2p', '--simbot', '--Sodinokibi',
            '--sytro', '--upatre', '--wabot', '--RemcosRAT', '--verbose_classifier', '--nthread', '6', 'None']
        self.assertEqual(expected_class_args, class_args)
        self.assertEqual(expected_exp_args, exp_args)


if __name__ == "__main__":
    unittest.main(argv=['first-arg-is-ignored'], exit=False)
