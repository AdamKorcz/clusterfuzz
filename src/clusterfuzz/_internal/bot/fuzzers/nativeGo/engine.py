# Copyright 2022 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os
from clusterfuzz.fuzz import engine


class Engine(engine.Engine)
	@property
	def name(self):
		return 'nativeGo'

	# Optional methods
	'''def _create_temp_corpus_dir(self, name):
	    """Create temporary corpus directory."""
	    new_corpus_directory = os.path.join(fuzzer_utils.get_temp_dir(), name)
	    engine_common.recreate_directory(new_corpus_directory)
	    return new_corpus_directory'''

	# Mandatory methods
	def prepare(self, corpus_dir, target_path, build_dir):
		os.chmod(target_path, 0o775)

		# Create corpus dir
		test_corpus_dir = "/tmp/test-clusterfuzz-corpus-dir"
		test_corpus_dir_exists = os.path.exists(test_corpus_dir)
		if not test_corpus_dir_exists:
			os.makedirs(test_corpus_dir)
    	return engine.FuzzOptions(test_corpus_dir, [], {})

    def fuzz(self, target_path, options, reproducers_dir, max_time):
	    runner = new_process.UnicodeProcessRunner(target_path)
	    fuzz_result = runner.run_and_wait(
        timeout=max_time,
        additional_args=["-test.fuzz=FuzzMain", "-test.fuzzcachedir /tmp/test-clusterfuzz-corpus-dir"],
        extra_env={})
	    log_lines = fuzz_result.output.splitlines()
	    print(log_lines)
        # TODO: parse output in case of a crash.
	
	def reproduce(self, target_path, input_path, arguments, max_time):
		raise NotImplementedError

	def minimize_corpus(self, target_path, arguments, input_dirs, output_dir,
                      reproducers_dir, max_time):
    	raise NotImplementedError


   	def minimize_testcase(self, target_path, arguments, input_path, output_path,
                        max_time):
	    raise NotImplementedError

	def cleanse(self, target_path, arguments, input_path, output_path, max_time):
		raise NotImplementedError