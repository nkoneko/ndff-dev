#include <string>
#include <vector>
#include <cstdlib>
extern "C" {
#include <ndpi/ndpi_typedefs.h>
#include <ndpi/ndpi_define.h>
#include <ndpi/ndpi_api.h>
#include <ndpi/ndpi_protocol_ids.h>
#include <pcap.h>
#include <ndff.h>
#include <arpa/inet.h>
#include <unistd.h>
}

#define IDLE_SCAN_PERIOD 10
#define MAX_IDLE_TIME 30000
#define IDLE_SCAN_BUDGET 1024
#define TICK_RESOLUTION 1000
#define MAX_NUM_READER_THREADS 16
#define NUM_ROOTS 512
#define MAX_NDPI_FLOWS 200000000

static u_int8_t quiet_mode = 0, json_flag = 0, msgpack_flag = 0, live_capture = 0, enable_protocol_guess = 1;
static char* _tag = "ndpi.flow";
static int _server_port = 24224;
static char *_server_addr = NULL;
static u_int8_t num_threads = 1;
static u_int8_t shutdown_app = 0, undetected_flows_deleted = 0;
static time_t capture_for = 0;
static time_t capture_until = 0;

typedef struct ndpi_workflow_prefs
{
	u_int8_t decode_tunnels;
	u_int8_t quiet_mode;
	u_int32_t num_roots;
	u_int32_t max_ndpi_flows;
} ndpi_workflow_prefs_t;

struct ndpi_workflow;
typedef void (*ndff_workflow_callback_ptr)(struct ndpi_workflow *, struct ndff_flow *, void *);

typedef struct ndpi_workflow
{
	u_int64_t last_time;
	struct ndpi_workflow_prefs prefs;
	ndff_callback __flow_detected_callback;
	void *__flow_detected_udata;
	ndff_callback __flow_giveup_callback;
	void *__flow_giveup_udata;
	pcap_t *pcap_handle;
	void **ndpi_flows_root;
	struct ndpi_detection_module_struct *ndpi_struct;
	u_int32_t num_allocated_flows;
} ndpi_workflow_t;

struct reader_thread
{
	struct ndpi_workflow *workflow;
	pthread_t pthread;
	u_int64_t last_idle_scan_time;
	u_int32_t idle_scan_idx;
	u_int32_t num_idle_flows;
	struct ndff_flow *idle_flows[IDLE_SCAN_BUDGET];
};

static struct reader_thread ndpi_thread_info[MAX_NUM_READER_THREADS];
static int core_affinity[MAX_NUM_READER_THREADS];
static char *_pcap_file[MAX_NUM_READER_THREADS];

static void breakPcapLoop(u_int16_t thread_id)
{
	if (ndpi_thread_info[thread_id].workflow->pcap_handle != NULL)
	{
		pcap_breakloop(ndpi_thread_info[thread_id].workflow->pcap_handle);
	}
}

void sigproc(int sig)
{
	static int called = 0;
	int thread_id;
	if (called) return; else called = 1;
	shutdown_app = 1;
	for (thread_id = 0; thread_id < num_threads; thread_id++)
	{
		breakPcapLoop(thread_id);
	}
}

static void parseOptions(int argc, char **argv)
{
	int do_capture = 0;
	char *__pcap_file = NULL, *bind_mask = NULL;
	int thread_id, opt;
	u_int num_cores = sysconf(_SC_NPROCESSORS_ONLN);
	while ((opt = getopt(argc, argv, "qti:p:s:m:n:")) != EOF)
	{
		switch (opt)
		{
			case 'q':
				quiet_mode = 1;
				break;
			case 't':
				_tag = optarg;
				break;
			case 'i':
				_pcap_file[0] = optarg;
				break;
			case 'p':
				_server_port = atoi(optarg);
				break;
			case 's':
				_server_addr = optarg;
				break;
			case 'm':
                if (strcmp(optarg, "json") == 0)
				{
                    json_flag = 1;
                }
				else if (strcmp((char *)optarg, "msgpack") == 0)
				{
                    msgpack_flag = 1;
				}
				break;
			case 'd':
				enable_protocol_guess = 0;
				break;
			case 'n':
				num_threads = atoi(optarg);
				break;
		}
		if (num_threads > MAX_NUM_READER_THREADS)
		{
			num_threads = MAX_NUM_READER_THREADS;
		}
		for (thread_id = 1; thread_id < num_threads; thread_id++)
		{
			_pcap_file[thread_id] = _pcap_file[0];
		}
#ifdef linux
		for(thread_id = 0; thread_id < num_threads; thread_id++)
		core_affinity[thread_id] = -1;

		if(num_cores > 1 && bind_mask != NULL) {
		char *core_id = strtok(bind_mask, ":");
		thread_id = 0;
		while(core_id != NULL && thread_id < num_threads) {
			core_affinity[thread_id++] = atoi(core_id) % num_cores;
			core_id = strtok(NULL, ":");
		}
		}
#endif
	}
}

class PcapFile
{
public:
    PcapFile(const char *filename)
    {
        char errbuf[PCAP_ERRBUF_SIZE];
        m_handle = pcap_open_offline(filename, errbuf);
    }

    const u_char *next(struct pcap_pkthdr &header)
    {
        return pcap_next(m_handle,  &header);
    }
    ~PcapFile()
    {
        pcap_close(m_handle);
    }
private:
    pcap_t *m_handle;
};

static inline u_int8_t is_proto(struct ndff_flow *flow, u_int16_t id)
{
	return (flow->detected_protocol.master_protocol == id) || (flow->detected_protocol.app_protocol == id);
}

static void _on_detect(struct ndff_flow *flow, void* param)
{
	printf("flow id: %d, master protocol: %d, app protocol: %d\n", flow->flow_id, flow->detected_protocol.master_protocol, flow->detected_protocol.app_protocol);
	if (is_proto(flow, NDPI_PROTOCOL_TLS))
	{
		printf("%s\n", flow->ssh_tls.client_requested_server_name);
	}
	else if (is_proto(flow, NDPI_PROTOCOL_DHCP))
	{
		char yiaddr[48];
		inet_ntop(AF_INET, &flow->dhcp.yiaddr, yiaddr, sizeof(yiaddr));
		printf("%s, %s, %u, %02x:%02x:%02x:%02x:%02x:%02x\n", flow->host_server_name, yiaddr, flow->dhcp.lease_time,
			flow->dhcp.macaddr[0],
			flow->dhcp.macaddr[1],
			flow->dhcp.macaddr[2],
			flow->dhcp.macaddr[3],
			flow->dhcp.macaddr[4],
			flow->dhcp.macaddr[5]
		);
	}
	else if (is_proto(flow, NDPI_PROTOCOL_DNS))
	{
		if (flow->dns.rsp_type == 1)
		{
			char rsp_addr[48];
			inet_ntop(AF_INET, &flow->dns.rsp_addr, rsp_addr, sizeof(rsp_addr));
			printf("%s, %s %u\n", flow->host_server_name, rsp_addr, flow->dns.rsp_type);
		}
		else if (flow->dns.rsp_type == 28)
		{
			char rsp_addr[INET6_ADDRSTRLEN];
			inet_ntop(AF_INET6, &flow->dns.rsp_addr, rsp_addr, sizeof(rsp_addr));
			printf("28 %s, %s %u\n", flow->host_server_name, rsp_addr, flow->dns.rsp_type);
		}
		else
		{
			printf("Skipped CNAME\n", flow->dns.rsp_type);
		}
	}
}

static inline void ndpi_workflow_set_flow_detected_callback(struct ndpi_workflow *workflow, ndff_callback callback, void *udata)
{
	workflow->__flow_detected_callback = callback;
	workflow->__flow_detected_udata = udata;
}

static inline void ndpi_workflow_set_flow_giveup_callback(struct ndpi_workflow *workflow, ndff_callback callback, void *udata)
{
	workflow->__flow_giveup_callback = callback;
	workflow->__flow_giveup_udata = udata;
}

static ndpi_workflow *ndpi_workflow_init(const struct ndpi_workflow_prefs *prefs, pcap_t *pcap_handle)
{
	struct ndpi_detection_module_struct *module;
	struct ndpi_workflow *workflow;

	set_ndpi_malloc(malloc), set_ndpi_free(free);
	set_ndpi_flow_malloc(malloc), set_ndpi_flow_free(free);

	module = ndpi_init_detection_module(ndpi_no_prefs);
	if (module == NULL)
	{
		exit(-1);
	}
	workflow = (struct ndpi_workflow*) ndpi_calloc(1, sizeof(struct ndpi_workflow));
	workflow->pcap_handle = pcap_handle;
	workflow->prefs = *prefs;
	workflow->ndpi_struct = module;

	workflow->ndpi_flows_root = (void**) ndpi_calloc(workflow->prefs.num_roots, sizeof(void *));
	return workflow;
}

static pcap_t *openPcapFileOrDevice(u_int16_t thread_id, const u_char *pcap_file)
{
	u_int snaplen = 1536;
	int promisc = 1;
	char pcap_error_buf[PCAP_ERRBUF_SIZE];
	pcap_t *pcap_handle = NULL;

	if ((pcap_handle = pcap_open_live((char*) pcap_file, snaplen, promisc, 500, pcap_error_buf)) == NULL)
	{
		capture_for = capture_until = 0;
		live_capture = 0;
		num_threads = 1;

		if ((pcap_handle = pcap_open_offline((char*) pcap_file, pcap_error_buf)) == NULL)
		{
			if (strstr((char*) pcap_file, (char*) ".pcap"))
				printf("ERROR: could not open pcap file %s: %s\n", pcap_file, pcap_error_buf);
			exit(-1);			
		}
		else
		{
			if (!quiet_mode)
			{
				printf("Reading packets from pcap file %s...\n", pcap_file);
			}
		}
	}
	else
	{
		live_capture = 1;
		if (!quiet_mode)
		{
			printf("Capturing live traffic from device %s...\n", pcap_file);
		}
	}
	return pcap_handle;
}

static void setupDetection(u_int16_t thread_id, pcap_t *pcap_handle)
{
	NDPI_PROTOCOL_BITMASK all;
	struct ndpi_workflow_prefs prefs;

	memset(&prefs, 0, sizeof(prefs));
	prefs.num_roots = NUM_ROOTS;
	prefs.max_ndpi_flows = MAX_NDPI_FLOWS;
	prefs.quiet_mode = quiet_mode;

	memset(&ndpi_thread_info[thread_id], 0 , sizeof(ndpi_thread_info[thread_id]));
	ndpi_thread_info[thread_id].workflow = ndpi_workflow_init(&prefs, pcap_handle);

	ndpi_workflow_set_flow_detected_callback(ndpi_thread_info[thread_id].workflow, _on_detect, (void*)(uintptr_t)thread_id);

	NDPI_BITMASK_SET_ALL(all);
	ndpi_set_protocol_detection_bitmask2(ndpi_thread_info[thread_id].workflow->ndpi_struct, &all);
	ndpi_finalize_initalization(ndpi_thread_info[thread_id].workflow->ndpi_struct);
}

static void ndpi_flow_info_freer(void *node)
{
	struct ndff_flow *flow = (struct ndff_flow*) node;

	if (flow->ndpi_flow)
	{
		ndpi_flow_free(flow->ndpi_flow);
		flow->ndpi_flow = NULL;
	}
	if (flow->src_id)
	{
		ndpi_free(flow->src_id);
		flow->src_id = NULL;
	}
	if (flow->dst_id)
	{
		ndpi_free(flow->dst_id);
		flow->dst_id = NULL;
	}
	if (flow->ssh_tls.server_names)
	{
		ndpi_free(flow->ssh_tls.server_names);
		flow->ssh_tls.server_names = NULL;
	}
	ndpi_free(flow);
}

static void ndpi_workflow_free(struct ndpi_workflow *workflow)
{
	u_int i;

	for (i = 0; i < workflow->prefs.num_roots; i++)
	{
		ndpi_tdestroy(workflow->ndpi_flows_root[i], ndpi_flow_info_freer);
	}

	ndpi_exit_detection_module(workflow->ndpi_struct);
	free(workflow->ndpi_flows_root);
	free(workflow);
}

static void terminateDetection(u_int16_t thread_id)
{
	ndpi_workflow_free(ndpi_thread_info[thread_id].workflow);
}

static void process_ndpi_collected_info(struct ndpi_workflow *workflow, struct ndff_flow *flow)
{
	u_int i;

	if (!flow->ndpi_flow) return;

	snprintf(flow->host_server_name, sizeof(flow->host_server_name), "%s", flow->ndpi_flow->host_server_name);
	if (is_proto(flow, NDPI_PROTOCOL_BITTORRENT))
	{
		u_int j, n = 0;
		for (i = 0, j = 0; j < sizeof(flow->bittorrent_hash) - 1; i++)
		{
			sprintf(&flow->bittorrent_hash[j], "%02X", flow->ndpi_flow->protos.bittorrent.hash[i]);
			j += 2, n += flow->ndpi_flow->protos.bittorrent.hash[i];
		}
		if (n == 0) flow->bittorrent_hash[0] = '\0';
	}
	else if (is_proto(flow, NDPI_PROTOCOL_DNS))
	{
		if (flow->ndpi_flow->protos.dns.rsp_type == 0x1)
			inet_ntop(AF_INET, &flow->ndpi_flow->protos.dns.rsp_addr.ipv4, flow->info, sizeof(flow->info));
		else
		{
			inet_ntop(AF_INET6, &flow->ndpi_flow->protos.dns.rsp_addr.ipv6, flow->info, sizeof(flow->info));
			ndpi_patchIPv6Address(flow->info);
		}
	}
	if (flow->ndpi_flow)
	{
		ndpi_flow_free(flow->ndpi_flow);
		flow->ndpi_flow = NULL;
	}
	if (flow->src_id)
	{
		ndpi_free(flow->src_id);
		flow->src_id = NULL;
	}
	if (flow->dst_id)
	{
		ndpi_free(flow->dst_id);
		flow->dst_id = NULL;
	}
}

static void node_proto_guess_walker(const void *node, ndpi_VISIT which, int depth, void *user_data)
{
	struct ndff_flow *flow = *(struct ndff_flow **) node;
	u_int16_t thread_id = *((u_int16_t *) user_data), proto;
	if ((which == ndpi_preorder) || (which == ndpi_leaf))
	{
		if ((!flow->is_detection_completed) && flow->ndpi_flow)
		{
			u_int8_t proto_guessed;
			flow->detected_protocol = ndpi_detection_giveup(ndpi_thread_info[0].workflow->ndpi_struct,
							flow->ndpi_flow, enable_protocol_guess, &proto_guessed);
		}
		process_ndpi_collected_info(ndpi_thread_info[thread_id].workflow, flow);
		proto = flow->detected_protocol.app_protocol ? flow->detected_protocol.app_protocol : flow->detected_protocol.master_protocol;
	}
}

static void node_idle_scan_walker(const void *node, ndpi_VISIT which, int depth, void *user_data)
{
	struct ndff_flow *flow = *(struct ndff_flow**) node;
	u_int16_t thread_id = *((u_int16_t*) user_data);

	printf("Idle Scan Walker. num_idle_flows -> %lu, preorder: %u, leaf: %u, which: %u\n", ndpi_thread_info[thread_id].num_idle_flows, ndpi_preorder, ndpi_leaf, which);
	if (ndpi_thread_info[thread_id].num_idle_flows == IDLE_SCAN_BUDGET)
		return;
	if ((which == ndpi_preorder) || (which == ndpi_leaf))
	{
		printf("Idle scan walker.\n");
		node_proto_guess_walker(node, which, depth, user_data);
		if ((flow->detected_protocol.app_protocol == NDPI_PROTOCOL_UNKNOWN) && !undetected_flows_deleted)
			undetected_flows_deleted = 1;
		if (flow->ndpi_flow)
		{
			ndpi_flow_free(flow->ndpi_flow);
			flow->ndpi_flow = NULL;
		}
		if (flow->src_id)
		{
			ndpi_free(flow->src_id);
			flow->src_id = NULL;
		}
		if (flow->dst_id)
		{
			ndpi_free(flow->dst_id);
			flow->dst_id = NULL;
		}
		ndpi_thread_info[thread_id].idle_flows[ndpi_thread_info[thread_id].num_idle_flows++] = flow;
	}
}

static void ndff_process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	struct ndpi_proto p;
	u_int8_t proto;
	u_int16_t type, vlan_id, offset, ip_offset;
	struct ndpi_iphdr *ipv4;
    struct ndpi_ipv6hdr *ipv6;
    union {
        u_int32_t u32;
        u_int8_t u8[4];
    } ipaddr;
	u_int64_t time;
	struct ndpi_tcphdr *tcph;
    struct ndpi_udphdr *udph;
    u_int16_t payload_len;
    u_int8_t *l4_payload;
    struct ndpi_id_struct *src, *dst;
    struct ndff_flow *flow;
    src = dst = NULL;
	char *errmsg = NULL;

	u_int16_t thread_id = *((u_int16_t*) args);
	u_int8_t *packet_checked = (u_int8_t*) malloc(header->caplen);
	memcpy(packet_checked, packet, header->caplen);

	tcph = NULL; udph = NULL; ipv4 = NULL; ipv6 = NULL;
	time = ((u_int64_t) header->ts.tv_sec) * 1000 + header->ts.tv_usec / (1000000 / 1000);
	if (ndpi_thread_info[thread_id].workflow->last_time > time)
	{
		time = ndpi_thread_info[thread_id].workflow->last_time;
	}
	ndpi_thread_info[thread_id].workflow->last_time = time;

	offset = ip_offset = ndff_detect_type(header, DLT_EN10MB, 0, packet_checked, &type, &vlan_id, &errmsg);
	offset = ndff_set_iphdr(header, type, packet_checked, offset, &ipv4, &ipv6, &proto);
	if (ipv4 == NULL && ipv6 == NULL) goto ignore;
	offset = ndff_set_l4hdr(header, packet_checked, offset, ipv4, ipv6, proto, &tcph, &udph, &l4_payload, &payload_len);
	flow = ndff_get_flow_info(ndpi_thread_info[thread_id].workflow->ndpi_flows_root,
				ndpi_thread_info[thread_id].workflow->prefs.num_roots,vlan_id, header->caplen, &src, &dst, ipv4, ipv6, tcph, udph);
	p = ndff_get_protocol(ndpi_thread_info[thread_id].workflow->ndpi_struct, proto, time, ipv4, ipv6, header->caplen - ip_offset, src, dst, _on_detect, NULL, flow);
	if (live_capture)
	{
		if (ndpi_thread_info[thread_id].last_idle_scan_time + IDLE_SCAN_PERIOD < ndpi_thread_info[thread_id].workflow->last_time)
		{
			printf("Last Idle Scan Time: %lu, Last Time: %lu, index: %u. root: %p\n", ndpi_thread_info[thread_id].last_idle_scan_time, ndpi_thread_info[thread_id].workflow->last_time,
						ndpi_thread_info[thread_id].idle_scan_idx,
						ndpi_thread_info[thread_id].workflow->ndpi_flows_root[ndpi_thread_info[thread_id].idle_scan_idx]);
			ndpi_twalk(ndpi_thread_info[thread_id].workflow->ndpi_flows_root[ndpi_thread_info[thread_id].idle_scan_idx], node_idle_scan_walker, &thread_id);
			while (ndpi_thread_info[thread_id].num_idle_flows > 0)
			{
				ndpi_tdelete(ndpi_thread_info[thread_id].idle_flows[--ndpi_thread_info[thread_id].num_idle_flows],
						&ndpi_thread_info[thread_id].workflow->ndpi_flows_root[ndpi_thread_info[thread_id].idle_scan_idx],
						ndff_flow_node_cmp);
				ndff_flow *flow = ndpi_thread_info[thread_id].idle_flows[ndpi_thread_info[thread_id].num_idle_flows];
				if (flow->ndpi_flow)
				{
					ndpi_flow_free(flow->ndpi_flow);
					flow->ndpi_flow = NULL;
				}
				if (flow->src_id)
				{
					ndpi_free(flow->src_id);
					flow->src_id = NULL;
				}
				if (flow->dst_id)
				{
					ndpi_free(flow->dst_id);
					flow->dst_id = NULL;
				}
				ndpi_free(ndpi_thread_info[thread_id].idle_flows[ndpi_thread_info[thread_id].num_idle_flows]);
			}
			if (++ndpi_thread_info[thread_id].idle_scan_idx == ndpi_thread_info[thread_id].workflow->prefs.num_roots)
			{
				ndpi_thread_info[thread_id].idle_scan_idx = 0;
			}
			ndpi_thread_info[thread_id].last_idle_scan_time = ndpi_thread_info[thread_id].workflow->last_time;
		}
	}
	return;
ignore:
	printf("Non-IP protocol.\n");
}

static void runPcapLoop(u_int16_t thread_id)
{
	if (!shutdown_app && ndpi_thread_info[thread_id].workflow->pcap_handle != NULL)
	{
		if (pcap_loop(ndpi_thread_info[thread_id].workflow->pcap_handle, -1, &ndff_process_packet, (u_char*) &thread_id) < 0)
		{
			printf("Error while reading pcap file: %s\n", pcap_geterr(ndpi_thread_info[thread_id].workflow->pcap_handle));
		}
	}
}

void *processing_thread(void *_thread_id)
{
	long thread_id = (long) _thread_id;
	char pcap_error_buffer[PCAP_ERRBUF_SIZE];
#if defined(linux) && defined(HAVE_PTHREAD_SETAFFINITY_NP)
	if (core_affinity[thread_id] >= 0)
	{
		cpu_set_t cpuset;

		CPU_ZERO(&cpuset);
		CPU_SET(core_affinity[thread_id], &cpuset);

		if (pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset) != 0)
		{
			fprintf(stderr, "Error while binding thread %ld to core %d\n", thread_id, core_affinity[thread_id]);
		}
		else
		{
			if (!quiet_mode)
			{
				printf("Running thread %ld on core %d...\n", thread_id, core_affinity[thread_id]);
			}
		}
	}
	else
#endif
	if (!quiet_mode)
	{
		printf("Running thread %ld...\n", thread_id);
	}
	runPcapLoop(thread_id);
	return NULL;
}

int main(int argc, char **argv)
{
	long thread_id;

	memset(ndpi_thread_info, 0, sizeof(ndpi_thread_info));
	parseOptions(argc, argv);
	signal(SIGINT, sigproc);

	for (thread_id = 0; thread_id < num_threads; thread_id++)
	{
		pcap_t *pcap;
		pcap = openPcapFileOrDevice(thread_id, (const u_char*) _pcap_file[thread_id]);
		setupDetection(thread_id, pcap);
	}

	int status;
	void *thd_res;
	for (thread_id = 0; thread_id < num_threads; thread_id++)
	{
		status = pthread_create(&ndpi_thread_info[thread_id].pthread, NULL, processing_thread, (void *) thread_id);
		if (status != 0)
		{
			fprintf(stderr, "error on create %ld thread\n", thread_id);
			exit(-1);
		}
	}

	for (thread_id = 0; thread_id < num_threads; thread_id++)
	{
		status = pthread_join(ndpi_thread_info[thread_id].pthread, &thd_res);
		if (status != 0)
		{
			fprintf(stderr, "error on join %ld thread\n", thread_id);
			exit(-1);
		}
		if (thd_res != NULL)
		{
			fprintf(stderr, "error on returned value of %ld joined thread\n", thread_id);
			exit(-1);
		}
	}

	for (thread_id = 0; thread_id < num_threads; thread_id++)
	{
		if (ndpi_thread_info[thread_id].workflow->pcap_handle != NULL)
		{
			pcap_close(ndpi_thread_info[thread_id].workflow->pcap_handle);
		}
		terminateDetection(thread_id);
	}

#if 0
	if (argc < 1)
	{
		return 0;
	}
	char *filename = argv[1];
    const u_char *packet;
    struct pcap_pkthdr header;
    u_int16_t type, vlan_id, offset, ip_offset;
    char *errmsg = NULL;

    struct ndpi_iphdr *ipv4;
    struct ndpi_ipv6hdr *ipv6;
    u_int8_t proto;
    union {
        u_int32_t u32;
        u_int8_t u8[4];
    } ipaddr;

	struct ndpi_detection_module_struct *detect_mod = ndpi_init_detection_module(ndpi_no_prefs);
	struct ndpi_proto protocol;
	u_int64_t time;

    struct ndpi_tcphdr *tcph;
    struct ndpi_udphdr *udph;
    u_int16_t payload_len;
    u_int8_t *l4_payload;
    void **trees;
    trees = (void**) calloc(1, sizeof(void *));

    struct ndpi_id_struct *src, *dst;
    struct ndff_flow *flow;
    src = dst = NULL;

	parseOptions(argc, argv);
	memset(ndpi_thread_info, 0, sizeof(ndpi_thread_info));
	signal(SIGINT, sigproc);

	NDPI_PROTOCOL_BITMASK all;
	NDPI_BITMASK_SET_ALL(all);
	ndpi_set_protocol_detection_bitmask2(detect_mod, &all);
	ndpi_finalize_initalization(detect_mod);

	char BUF[1024];

    PcapFile pcap(filename);

    int cnt = 0;
    while (packet = pcap.next(header))
	{
		tcph = NULL; udph = NULL; ipv4 = NULL; ipv6 = NULL;
		time = ((u_int64_t) header.ts.tv_sec) * 1000 + header.ts.tv_usec / (1000000 / 1000);
        offset = ip_offset = ndff_detect_type(&header, DLT_EN10MB, 0, packet, &type, &vlan_id, &errmsg);
        offset = ndff_set_iphdr(&header, type, packet, offset, &ipv4, &ipv6, &proto);
		if (ipv4 == NULL && ipv6 == NULL) continue;
        offset = ndff_set_l4hdr(&header, packet, offset, ipv4, ipv6, proto, &tcph, &udph, &l4_payload, &payload_len);
        flow = ndff_get_flow_info(trees,1,vlan_id, header.caplen, &src, &dst, ipv4, ipv6, tcph, udph);
		protocol = ndff_get_protocol(detect_mod, proto, time, ipv4, ipv6, header.caplen - ip_offset, src, dst, _on_detect, NULL, flow);
		cnt++;
	}
	printf("Count: %d\n", cnt);
	free(trees);
#endif
	return 0;
}
