#!/usr/bin/env python3

import argparse
import logging
import os
import subprocess
import sys

# xIM user (activity will be excluded)
xIMuid = os.getuid()

# Initialize global data structures
sysdig_field_for = {
	'process': 'proc_name',
	'container': 'container_id',
	'pod': 'k8s_pod_name'
}
written_paths = {}
read_paths = set()
cross_app_flows = set()

# Program entry point
def main(argv):
	parse_arguments()
	start_logging()
	print_entry_message()
	run_sysdig_process()
	analyze_sysdig_output()

# Command line arguments translated to program state
def parse_arguments():
	parser = argparse.ArgumentParser()
	parser.add_argument('-d', '--debug', help='Emit debug messages (if logging active)', action='store_true')
	parser.add_argument('-g', '--granularity', help='Isolation monitoring granularity (process / container / pod)')
	args = parser.parse_args()
	global debug
	debug = args.debug
	global granularity
	granularity = 'process'
	if args.granularity == 'container' or args.granularity == 'pod':
		granularity = args.granularity

# Define format for log output
def start_logging():
	log_level = logging.INFO
	if debug:
		log_level = logging.DEBUG
	log_datefmt='%Y-%m-%d %H:%M:%S'
	log_format='%(levelname)s: %(asctime)s - %(message)s\r'
	logging.basicConfig(format=log_format, datefmt=log_datefmt, level=log_level)

# Let user know that monitoring has started
def print_entry_message():
	entry_message = '''
		xApp Isolation Monitor
	'''
	logging.info(entry_message)

# Run a single instance of Sysdig
# If Kubernetes is being used, Sydig has to contact the API server
# The API server is assumed to be listening on localhost, port 8080
def run_sysdig_process():
	sysdig_output_format = get_sysdig_output_format()
	sysdig_filter = get_sysdig_filter()
	if granularity == 'pod':
		sysdig_invocation = ['sudo', 'sysdig', '-k', 'http://127.0.0.1:8080', '-p', sysdig_output_format, sysdig_filter]
	else:
		sysdig_invocation = ['sudo', 'sysdig', '-p', sysdig_output_format, sysdig_filter]
	global sysdig_process
	sysdig_process = subprocess.Popen(sysdig_invocation, stdout=subprocess.PIPE, text=True, bufsize=1)

# Define the set of output fields needed, including Kubernetes-specific ones
def get_sysdig_output_format():
	sysdig_output_multiline_format = '''
		evt_io_dir:%evt.io_dir
		fd_name:%fd.name
		proc_name:%proc.name
		container_id:%container.id
	'''
	if granularity == 'pod':
		sysdig_output_multiline_format += 'k8s_pod_name:%k8s.pod.name'
	sysdig_output_format = " ".join(sysdig_output_multiline_format.split())
	return sysdig_output_format

# Provide Sysdig with a specification of what to monitor
# This will be used to define the eBPF instrumentation needed
# Specifically: (i) log I/O events, (ii) do not log events from the user that xIM runs as
def get_sysdig_filter():
	include_target_activity = 'evt.category=file and (evt.is_io_read=true or evt.is_io_write=true)'
	exclude_xim_user_activity = f' and user.uid!={xIMuid}'
	sysdig_filter = include_target_activity + exclude_xim_user_activity
	logging.debug(f'Sysdig filter: {sysdig_filter}')
	return sysdig_filter

# Transform the Sydig output into a Python dictionary for subsequent processing
def analyze_sysdig_output():
	for sysdig_output in sysdig_process.stdout:
		sysdig_field_pairs = dict(sysdig_field_pair.split(':', 1) for sysdig_field_pair in sysdig_output.split())
		process_io_event(sysdig_field_pairs)

# Bifurcate the event processing for read and write events
def process_io_event(io_event):
	io_dir = io_event['evt_io_dir']
	match io_dir:
		case 'write':
			process_write(io_event)
		case 'read':
			process_read(io_event)

# When a write occurs, the path that was written is tracked
# The path is used as a key to index into a set of writers
# The set is updated to contain the current writer
def process_write(io_event):
	current_path = io_event['fd_name']
	current_writer = io_event[sysdig_field_for[granularity]]
	# If the current path has not been written to before, add it to the set of paths that have been written
	# Also, add the current writer to the set of those that have written to the current path
	if current_path not in written_paths:
		written_paths[current_path] = { current_writer }
		logging.debug(f'Adding {current_writer} to apps that have written to {current_path}')
	else:
		# If the current process / container / pod is in the set of writers seen, do nothing
		# Otherwise, add the current process / container / pod to the set of writers for the current path
		writing_apps = written_paths[current_path]
		if current_writer not in writing_apps:
			writing_apps.add(current_writer)
			logging.debug(f'Adding {current_writer} to apps that have written to {current_path}')

# When a read occurs, check if the path read has been written to
def process_read(io_event):
	current_path = io_event['fd_name']
	current_reader = io_event[sysdig_field_for[granularity]]
	# Lookup a global data structure to check if the current path has been written to
	if current_path in written_paths:
		# Disregard self-loops -- i.e. the case where the current reader has written to the path 
		writing_apps = written_paths[current_path]
		other_writing_apps = writing_apps.copy()
		other_writing_apps.discard(current_reader)
		if debug:
			if (current_path, current_reader) not in read_paths:
				logging.debug(f'Reading app is {current_reader}')
				logging.debug(f'Read path {current_path} has been written to by apps {writing_apps}')
				logging.debug(f'Read path {current_path} has been written to by other apps {other_writing_apps} (after discard)')
				read_paths.add((current_path, current_reader))
				logging.debug(f'Read path set is {str(read_paths)}')
		# If the specific cross flow -- i.e. <writer, path, reader> has not been reported, do so
		if other_writing_apps:
			for writing_app in other_writing_apps:
				if (writing_app, current_path, current_reader) not in cross_app_flows:
					process_cross_app_flow(writing_app, current_path, current_reader)

# Output a description of the granularity at which cross-flows are being tracked
# Specifiy the newly encountered writer, path, and reader
def process_cross_app_flow(writer, path, reader):
	cross_app_flows.add((writer, path, reader))
	logging.warning(f'Cross-{granularity} flow: {writer} -> {path} -> {reader}')

if __name__ == '__main__':
	main(sys.argv)
