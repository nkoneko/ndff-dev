project('ndff2', 'c', 'cpp',
    version: '0.1.0',
    license: 'GPL',
    default_options: ['c_std=gnu11', 'cpp_std=c++17']
)

ndpi_deps = dependency('libndpi', version: '>=2.8')
msgpack_deps = dependency('msgpack', version: '>=3.0')
json_deps = dependency('json-c', version: '>=0.12')
pcap_deps = dependency('libpcap', version: '>=1.9')
gtest_deps = dependency('gtest', main: true, version: '>=1.10')
gmock_deps = dependency('gmock', version: '>=1.10')
thread_dep = dependency('threads')

inc = include_directories('include')
libndff = shared_library('ndff', ['ndff.c', 'ndff_util.c'],
    include_directories: inc,
    dependencies: [
        ndpi_deps,
        msgpack_deps,
        json_deps,
        pcap_deps,
        thread_dep
    ],
    install: true)
executable('ndff', 'main.cpp', include_directories: inc, link_with: libndff, dependencies: [
        pcap_deps,
        ndpi_deps,
        thread_dep
], install: true)

pcap_files = [
    'google_ssl',
    'http_over_vlan',
    'quic',
]
foreach pcap: pcap_files
    configure_file(input: 'pcap/@0@.pcap'.format(pcap), output:'@0@.pcap'.format(pcap), copy: true)
endforeach

test = executable('ndff_test', 'test.cpp',
    include_directories: inc,
    link_with: libndff,
    dependencies:[
        gtest_deps,
        gmock_deps,
        pcap_deps,
        ndpi_deps,
        thread_dep
    ])
test('Test ndff2', test)
