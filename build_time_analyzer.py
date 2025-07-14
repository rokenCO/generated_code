#!/usr/bin/env python3
"""
Build Time Analyzer for C++ Projects with time_wrapper.sh

This script parses the compilation_times.log output from time_wrapper.sh
to calculate compilation times for shared objects (.so files) based on 
their constituent object files and linking times.

Usage:
    python build_analyzer.py [compilation_times.log] [options]
"""

import re
import sys
import argparse
from collections import defaultdict, namedtuple
from pathlib import Path
import json

# Data structures
CompilationInfo = namedtuple('CompilationInfo', ['obj_file', 'source_file', 'time', 'command'])
LinkingInfo = namedtuple('LinkingInfo', ['so_file', 'time', 'objects', 'command'])

class BuildTimeAnalyzer:
    def __init__(self, verbose=False):
        self.verbose = verbose
        self.object_times = {}  # obj_file -> CompilationInfo
        self.linking_info = {}  # so_file -> LinkingInfo
        self.so_dependencies = defaultdict(set)  # so_file -> set of object files
        
        # Regex patterns for parsing time_wrapper.sh output
        self.patterns = {
            # Match the timing log format: "command finished in X.XXX seconds"
            'timing_line': re.compile(r'^(.+) finished in ([\d.]+) seconds$'),
            
            # Extract object file compilation: -o file.o -c source.cpp
            'compile_obj': re.compile(r'.*-o\s+(\S+\.o)\s+.*-c\s+(\S+\.(cpp|cc|c\+\+|cxx|c))'),
            
            # Extract shared object linking: -o libname.so [objects...]
            'link_so': re.compile(r'.*-o\s+(\S+\.so)\s+(.*)'),
            
            # Extract object files from arguments
            'objects_in_args': re.compile(r'(\S+\.o)'),
            
            # Check if it's a shared library build (has -shared flag)
            'is_shared': re.compile(r'.*-shared.*'),
        }
    
    def parse_timing_log(self, filename="compilation_times.log"):
        """Parse the compilation_times.log file."""
        try:
            with open(filename, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
        except FileNotFoundError:
            print(f"Error: File '{filename}' not found.")
            return False
        
        print(f"Parsing {len(lines)} lines from {filename}...")
        
        for line_num, line in enumerate(lines, 1):
            line = line.strip()
            if not line:
                continue
            
            # Parse timing line
            timing_match = self.patterns['timing_line'].match(line)
            if not timing_match:
                if self.verbose:
                    print(f"Warning: Could not parse line {line_num}: {line}")
                continue
            
            command = timing_match.group(1)
            time_taken = float(timing_match.group(2))
            
            # Check if this is object file compilation
            if obj_match := self.patterns['compile_obj'].search(command):
                obj_file = obj_match.group(1)
                source_file = obj_match.group(2)
                
                self.object_times[obj_file] = CompilationInfo(
                    obj_file, source_file, time_taken, command
                )
                
                if self.verbose:
                    print(f"Object compilation: {obj_file} from {source_file} -> {time_taken:.3f}s")
            
            # Check if this is shared object linking
            elif (so_match := self.patterns['link_so'].search(command)) and \
                 self.patterns['is_shared'].search(command):
                
                so_file = so_match.group(1)
                link_args = so_match.group(2)
                
                # Extract object files from linking arguments
                objects = set(self.patterns['objects_in_args'].findall(link_args))
                
                self.linking_info[so_file] = LinkingInfo(
                    so_file, time_taken, objects, command
                )
                self.so_dependencies[so_file].update(objects)
                
                if self.verbose:
                    print(f"SO linking: {so_file} with {len(objects)} objects -> {time_taken:.3f}s")
                    if objects and self.verbose:
                        print(f"  Objects: {', '.join(sorted(objects))}")
            
            # Check if this is executable linking (for completeness)
            elif so_match := self.patterns['link_so'].search(command):
                # This might be an executable, not a shared object
                if self.verbose:
                    target = so_match.group(1)
                    print(f"Executable linking: {target} -> {time_taken:.3f}s")
        
        return True
    
    def calculate_so_times(self):
        """Calculate total compilation time for each shared object."""
        so_times = {}
        
        for so_file, link_info in self.linking_info.items():
            objects = link_info.objects
            total_compile_time = 0
            found_objects = 0
            missing_objects = []
            object_details = []
            
            # Sum up compilation times for all object files in this .so
            for obj_file in objects:
                if obj_file in self.object_times:
                    obj_info = self.object_times[obj_file]
                    total_compile_time += obj_info.time
                    found_objects += 1
                    object_details.append({
                        'obj_file': obj_file,
                        'source_file': obj_info.source_file,
                        'time': obj_info.time
                    })
                else:
                    missing_objects.append(obj_file)
            
            link_time = link_info.time
            total_time = total_compile_time + link_time
            
            so_times[so_file] = {
                'total_time': total_time,
                'compile_time': total_compile_time,
                'link_time': link_time,
                'object_count': len(objects),
                'found_objects': found_objects,
                'missing_objects': missing_objects,
                'object_details': object_details,
                'avg_time_per_object': total_compile_time / found_objects if found_objects > 0 else 0,
                'link_command': link_info.command
            }
        
        return so_times
    
    def find_slowest_objects(self, top_n=10):
        """Find the slowest compiling object files."""
        sorted_objects = sorted(self.object_times.items(), 
                              key=lambda x: x[1].time, 
                              reverse=True)
        return sorted_objects[:top_n]
    
    def print_report(self, so_times, sort_by='total_time', top_n=None):
        """Print a formatted report of shared object compilation times."""
        if not so_times:
            print("No shared object timing data found.")
            return
        
        # Sort by specified metric
        sorted_sos = sorted(so_times.items(), 
                          key=lambda x: x[1][sort_by], 
                          reverse=True)
        
        if top_n:
            sorted_sos = sorted_sos[:top_n]
        
        print(f"\n{'='*90}")
        print(f"BUILD TIME ANALYSIS REPORT (sorted by {sort_by})")
        print(f"{'='*90}")
        
        print(f"{'Shared Object':<35} {'Total':<8} {'Compile':<8} {'Link':<8} {'Objects':<8} {'Avg/Obj':<8} {'Missing':<7}")
        print(f"{'-'*90}")
        
        for so_file, times in sorted_sos:
            so_name = Path(so_file).name[:34]  # Truncate long names
            missing_count = len(times['missing_objects'])
            
            print(f"{so_name:<35} "
                  f"{times['total_time']:>7.1f}s "
                  f"{times['compile_time']:>7.1f}s "
                  f"{times['link_time']:>7.1f}s "
                  f"{times['found_objects']:>3}/{times['object_count']:<3} "
                  f"{times['avg_time_per_object']:>7.1f}s "
                  f"{missing_count:>6}")
            
            if self.verbose and times['missing_objects']:
                print(f"  Missing timing for: {', '.join(times['missing_objects'][:3])}"
                      + (f" ... and {len(times['missing_objects']) - 3} more" 
                         if len(times['missing_objects']) > 3 else ""))
        
        # Summary statistics
        total_compile = sum(t['compile_time'] for t in so_times.values())
        total_link = sum(t['link_time'] for t in so_times.values())
        total_objects = sum(t['object_count'] for t in so_times.values())
        found_objects = sum(t['found_objects'] for t in so_times.values())
        
        print(f"\n{'='*90}")
        print(f"SUMMARY:")
        print(f"  Total compilation time: {total_compile:.1f}s ({total_compile/60:.1f} min)")
        print(f"  Total linking time: {total_link:.1f}s")
        print(f"  Total build time: {total_compile + total_link:.1f}s ({(total_compile + total_link)/60:.1f} min)")
        print(f"  Total objects: {total_objects} (found timing for {found_objects})")
        print(f"  Average time per object: {total_compile/found_objects:.1f}s" if found_objects > 0 else "")
        print(f"  Shared objects analyzed: {len(so_times)}")
        
        # Show slowest individual object files
        slowest_objects = self.find_slowest_objects(5)
        if slowest_objects:
            print(f"\n  SLOWEST OBJECT FILES:")
            for obj_file, info in slowest_objects:
                obj_name = Path(obj_file).name
                src_name = Path(info.source_file).name
                print(f"    {obj_name:<25} {src_name:<25} {info.time:>6.1f}s")
    
    def print_detailed_so_report(self, so_file, so_times):
        """Print detailed breakdown for a specific shared object."""
        if so_file not in so_times:
            print(f"No data found for {so_file}")
            return
        
        times = so_times[so_file]
        print(f"\nDETAILED REPORT FOR: {so_file}")
        print(f"{'='*80}")
        print(f"Total time: {times['total_time']:.1f}s")
        print(f"Compilation time: {times['compile_time']:.1f}s")
        print(f"Linking time: {times['link_time']:.1f}s")
        print(f"Objects: {times['found_objects']}/{times['object_count']}")
        
        if times['object_details']:
            print(f"\nOBJECT FILE BREAKDOWN:")
            print(f"{'Object File':<30} {'Source File':<30} {'Time':<8}")
            print(f"{'-'*70}")
            
            # Sort by compilation time
            sorted_objects = sorted(times['object_details'], 
                                  key=lambda x: x['time'], reverse=True)
            
            for obj in sorted_objects:
                obj_name = Path(obj['obj_file']).name[:29]
                src_name = Path(obj['source_file']).name[:29]
                print(f"{obj_name:<30} {src_name:<30} {obj['time']:>7.1f}s")
    
    def export_json(self, so_times, filename):
        """Export results to JSON for further analysis."""
        export_data = {
            'so_times': so_times,
            'object_times': {k: {
                'obj_file': v.obj_file,
                'source_file': v.source_file, 
                'time': v.time, 
                'command': v.command
            } for k, v in self.object_times.items()},
            'linking_info': {k: {
                'so_file': v.so_file,
                'time': v.time, 
                'objects': list(v.objects), 
                'command': v.command
            } for k, v in self.linking_info.items()}
        }
        
        with open(filename, 'w') as f:
            json.dump(export_data, f, indent=2)
        
        print(f"Data exported to {filename}")

def main():
    parser = argparse.ArgumentParser(description='Analyze C++ build times from time_wrapper.sh log')
    parser.add_argument('input_file', nargs='?', default='compilation_times.log',
                       help='Timing log file to analyze (default: compilation_times.log)')
    parser.add_argument('-v', '--verbose', action='store_true', 
                       help='Enable verbose output')
    parser.add_argument('-s', '--sort-by', 
                       choices=['total_time', 'compile_time', 'link_time', 'object_count'],
                       default='total_time', help='Sort results by metric')
    parser.add_argument('-n', '--top', type=int, help='Show only top N results')
    parser.add_argument('-d', '--detail', help='Show detailed breakdown for specific .so file')
    parser.add_argument('-j', '--json', help='Export results to JSON file')
    
    args = parser.parse_args()
    
    analyzer = BuildTimeAnalyzer(verbose=args.verbose)
    
    if not analyzer.parse_timing_log(args.input_file):
        sys.exit(1)
    
    so_times = analyzer.calculate_so_times()
    
    if args.detail:
        analyzer.print_detailed_so_report(args.detail, so_times)
    else:
        analyzer.print_report(so_times, sort_by=args.sort_by, top_n=args.top)
    
    if args.json:
        analyzer.export_json(so_times, args.json)

if __name__ == '__main__':
    main()