project('ndff2', 'c', 'cpp',
    version: '0.1.0',
    license: 'GPL',
    default_options: ['c_std=gnu11', 'cpp_std=c++17']
)

ndpi_deps = dependency('libndpi', version: '>=2.8')
msgpack_deps = dependency('msgpack', version: '>=3.2')
json_deps = dependency('json-c', version: '>=0.13')
pcap_deps = dependency('libpcap', version: '>=1.9')
gtest_deps = dependency('gtest', main: true, version: '>=1.10')
gmock_deps = dependency('gmock', version: '>=1.10')

inc = include_directories('include')
libndff = shared_library('libndff', ['ndff.c', 'ndff_util.c'],
    include_directories: inc,
    dependencies: [
        ndpi_deps,
        msgpack_deps,
        json_deps,
        pcap_deps
    ],
    install: true)
executable('ndff', 'main.c', include_directories: inc, link_with: libndff, install: true)

pcap_files = [
    'google_ssl',
    'http_over_vlan'
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
        pcap_deps
    ])
test('Test ndff2', test)
