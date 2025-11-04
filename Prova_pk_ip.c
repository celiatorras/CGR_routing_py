#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <string.h>
#include <time.h>
#include <ctype.h>

typedef uint32_t u32_t;
typedef uint16_t u16_t;
typedef uint8_t  u8_t;

struct ip6_addr {
    u32_t addr[4];
    // u8_t zone; // no considerem zone aquí
};
typedef struct ip6_addr ip6_addr_t;

int ip6_addr_to_str(const ip6_addr_t *a, char *buf, size_t buflen) {
    if (!a || !buf) return -1;
    unsigned char tmp[16];
    for (int i = 0; i < 4; ++i) {
        uint32_t w = htonl(a->addr[i]);
        tmp[i*4 + 0] = (w >> 24) & 0xFF;
        tmp[i*4 + 1] = (w >> 16) & 0xFF;
        tmp[i*4 + 2] = (w >> 8 ) & 0xFF;
        tmp[i*4 + 3] = (w >> 0 ) & 0xFF;
    }
    if (!inet_ntop(AF_INET6, tmp, buf, (socklen_t)buflen)) return -1;
    return 0;
}

long ipv6_to_nodeid(const char *ip6) {

    // Node 0 (id = 1)
    if (strcmp(ip6, "fd00:01::1") == 0) return 1;
    if (strcmp(ip6, "fd00:1::1") == 0) return 1; //todo

    // Node 1 (id = 2)
    if (strcmp(ip6, "fd00:01::2") == 0) return 2;
    if (strcmp(ip6, "fd00:12::1") == 0) return 2;
    if (strcmp(ip6, "fd00::1") == 0) return 2;
    if (strcmp(ip6, "fd00::2") == 0) return 2;

    // Node 2 (id = 3)
    if (strcmp(ip6, "fd00:12::2") == 0) return 3;
    if (strcmp(ip6, "fd00:23::2") == 0) return 3;
    if (strcmp(ip6, "fd00:22::1") == 0) return 3;
    if (strcmp(ip6, "fd00:22::2") == 0) return 3;

    // Node 3 (id = 4)
    if (strcmp(ip6, "fd00:23::3") == 0) return 4;
    if (strcmp(ip6, "fd00:33::1") == 0) return 4;
    if (strcmp(ip6, "fd00:33::2") == 0) return 4;

    return -1;
}


int main(void) {
    u32_t _v_tc_fl = 0x60000000;     // version(4) + traffic class(8) + flow label(20) 
    u16_t _plen = 200;               // payload length 
    u8_t  _hoplim = 64;              // hop limit -> lifetime 
    ip6_addr_t local;
    ip6_addr_t dest;

    memset(&dest, 0, sizeof(dest));
    unsigned char tmpbuf[16];

    if (inet_pton(AF_INET6, "fd00:01::1", tmpbuf) != 1) {
        fprintf(stderr, "inet_pton local address failed\n");
        return 1;
    }
    for (int i=0;i<4;i++) {
        uint32_t w = (tmpbuf[i*4+0] << 24) | (tmpbuf[i*4+1] << 16) | (tmpbuf[i*4+2] << 8) | (tmpbuf[i*4+3]);
        local.addr[i] = ntohl(w);
    }

    if (inet_pton(AF_INET6, "fd00:23::3", tmpbuf) != 1) {
        fprintf(stderr, "inet_pton dest failed\n");
        return 1;
    }
    for (int i=0;i<4;i++) {
        uint32_t w = (tmpbuf[i*4+0] << 24) | (tmpbuf[i*4+1] << 16) | (tmpbuf[i*4+2] << 8) | (tmpbuf[i*4+3]);
        dest.addr[i] = ntohl(w);
    }

    //conver address to string
    char curr_node_s[INET6_ADDRSTRLEN], dst_s[INET6_ADDRSTRLEN]; 

    if (ip6_addr_to_str(&local, curr_node_s, sizeof(curr_node_s)) != 0) { 
        fprintf(stderr, "ip6_addr_to_str local address failed\n"); return 1;
    } 
    
    if (ip6_addr_to_str(&dest, dst_s, sizeof(dst_s)) != 0) { 
        fprintf(stderr, "ip6_addr_to_str dest failed\n"); return 1; 
    }

    printf("local textual: %s\n", curr_node_s);
    printf("dst textual: %s\n", dst_s);
    printf("size(_plen)=%u hoplim=%u\n", _plen, _hoplim);

    //python initialize
    Py_Initialize();
    if (!Py_IsInitialized()) {
        fprintf(stderr, "Python not initialized\n");
        return 1;
    }

    PyObject *sys_path = PySys_GetObject("path");
    PyObject *py_pth = PyUnicode_FromString("."); 
    PyList_Append(sys_path, py_pth);
    Py_DECREF(py_pth);

    PyObject *pModule = PyImport_ImportModule("py_cgr_lib.py_cgr_lib");
    if (!pModule) {
        PyErr_Print();
        fprintf(stderr, "ERROR: cannot import py_cgr_lib.py_cgr_lib\n");
        Py_Finalize();
        return 1;
    }

    PyObject *py_cp_load = PyObject_GetAttrString(pModule, "cp_load");
    PyObject *py_cgr_yen = PyObject_GetAttrString(pModule, "cgr_yen");
    PyObject *py_fwd_candidate = PyObject_GetAttrString(pModule, "fwd_candidate");
    PyObject *py_ipv6_packet_cls = PyObject_GetAttrString(pModule, "ipv6_packet");

    /* ------------------ cp_load ------------------ */
    PyObject *args_load = PyTuple_New(2);
    PyTuple_SetItem(args_load, 0, PyUnicode_FromString("contact_plans/cgr_tutorial.txt"));
    PyTuple_SetItem(args_load, 1, PyLong_FromLong(5000));
    PyObject *contact_plan = PyObject_CallObject(py_cp_load, args_load);
    Py_DECREF(args_load);
    if (!contact_plan) {
        PyErr_Print();
        fprintf(stderr, "ERROR: cp_load failed\n");
        goto py_cleanup_funcs;
    }

    /* ------------------ cgr_yen ------------------ */
    long curr_node = ipv6_to_nodeid(curr_node_s);
    long dest_node   = ipv6_to_nodeid(dst_s);
    if (curr_node < 0 || dest_node < 0) {
        fprintf(stderr, "Mapping IPv6->node failed: src=%ld dst=%ld\n", curr_node, dest_node);
        goto py_cleanup_contact_plan;
    }

    double curr_time = (double)time(NULL);
    PyObject *args_yen = PyTuple_New(5);
    PyTuple_SetItem(args_yen, 0, PyLong_FromLong(curr_node));
    PyTuple_SetItem(args_yen, 1, PyLong_FromLong(dest_node));
    PyTuple_SetItem(args_yen, 2, PyFloat_FromDouble(curr_time));
    PyTuple_SetItem(args_yen, 3, contact_plan);
    PyTuple_SetItem(args_yen, 4, PyLong_FromLong(10)); 
    PyObject *routes = PyObject_CallObject(py_cgr_yen, args_yen);
    Py_DECREF(args_yen);
    if (!routes) {
        PyErr_Print();
        fprintf(stderr, "ERROR: cgr_yen failed\n");
        goto py_cleanup_contact_plan;
    }

    /* ------------------ ipv6_packet ------------------ */
    long size = _plen;
    long deadline = _hoplim*100000; //multiplying factor to transform to lifetime
    uint8_t tc = (uint8_t)((_v_tc_fl >> 20) & 0xFF); // traffic class (8 bits) 
    uint8_t dscp = (uint8_t)(tc >> 2);               // DSCP = TC[7:2] (6 bits)

    PyObject *args_pkt = PyTuple_New(4);
    PyTuple_SetItem(args_pkt, 0, PyLong_FromLong(dest_node));
    PyTuple_SetItem(args_pkt, 1, PyLong_FromLong(size));
    PyTuple_SetItem(args_pkt, 2, PyLong_FromLong(deadline));
    PyTuple_SetItem(args_pkt, 3, PyLong_FromLong(dscp));
    PyObject *ipv6pkt = PyObject_CallObject(py_ipv6_packet_cls, args_pkt);
    Py_DECREF(args_pkt);
    if (!ipv6pkt) {
        PyErr_Print();
        fprintf(stderr, "ERROR: creating ipv6_packet failed\n");
        goto py_cleanup_routes;
    }

    /* ------------------ fwd_candidate ------------------ */
    PyObject *excluded_nodes = PyList_New(0);
    PyObject *args_fwd = PyTuple_New(6);
    PyTuple_SetItem(args_fwd, 0, PyFloat_FromDouble(curr_time));
    PyTuple_SetItem(args_fwd, 1, PyLong_FromLong(curr_node));
    PyTuple_SetItem(args_fwd, 2, contact_plan);
    PyTuple_SetItem(args_fwd, 3, ipv6pkt);
    PyTuple_SetItem(args_fwd, 4, routes);
    PyTuple_SetItem(args_fwd, 5, excluded_nodes);
    PyObject *candidates = PyObject_CallObject(py_fwd_candidate, args_fwd);
    Py_DECREF(args_fwd);
    if (!candidates) {
        PyErr_Print();
        fprintf(stderr, "ERROR: fwd_candidate failed\n");
        goto py_cleanup_pkt;
    }

    //we check the next hop for the best route
    if (PyList_Check(candidates) && PyList_Size(candidates) > 0) {
        PyObject *first = PyList_GetItem(candidates, 0); /* borrowed */
        PyObject *pNextNode = PyObject_GetAttrString(first, "next_node");
        if (pNextNode) {
            if (PyLong_Check(pNextNode)) {
                long next_node = PyLong_AsLong(pNextNode);
                printf("Next hop node id: %ld\n", next_node);
            } else if (pNextNode == Py_None) {
                printf("Next hop: None\n");
            } else {
                printf("Next hop: (non-int)\n");
            }
            Py_DECREF(pNextNode);
        } else {
            PyErr_Clear();
            printf("Candidate object has no attribute next_node\n");
        }
    } else {
        printf("No candidate routes returned (list empty or not a list)\n");
    }

    Py_DECREF(candidates);
    py_cleanup_pkt:
    Py_DECREF(ipv6pkt);
    py_cleanup_routes:
    Py_DECREF(routes);
    py_cleanup_contact_plan:
    Py_DECREF(contact_plan);
    py_cleanup_funcs:
    Py_XDECREF(py_cp_load);
    Py_XDECREF(py_cgr_yen);
    Py_XDECREF(py_fwd_candidate);
    Py_XDECREF(py_ipv6_packet_cls);
    py_cleanup_module:
    Py_DECREF(pModule);
    Py_Finalize();
    return 0;
}