//needed library --> export LD_LIBRARY_PATH="/home/celia/Baixades/ENTER/lib:$LD_LIBRARY_PATH"
//compile --> gcc Prova_pk_ip.c -o Prova_pk_ip $(python3-config --cflags --ldflags --embed)
//execute --> ./Prova_pk_ipa

#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <string.h>
#include <time.h>
#include <ctype.h>

typedef uint32_t u32_t; //4 bytes
typedef uint16_t u16_t; //2 bytes
typedef uint8_t  u8_t;  //1 byte

struct ip6_addr {
    u32_t addr[4];
    // u8_t zone; // todo
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
    /*
    // Node 0
    if (strcmp(ip6, "fd00:01::1") == 0) return 1;
    if (strcmp(ip6, "fd00:1::1") == 0) return 1;

    // Node 1 
    if (strcmp(ip6, "fd00:01::2") == 0) return 10;
    if (strcmp(ip6, "fd00:1::2") == 0) return 10;
    if (strcmp(ip6, "fd00:12::1") == 0) return 12;

    // Node 2
    if (strcmp(ip6, "fd00:12::2") == 0) return 21;
    if (strcmp(ip6, "fd00:23::2") == 0) return 23;

    // Node 3
    if (strcmp(ip6, "fd00:23::3") == 0) return 32;
    */

    //others for experimentation
    if (strcmp(ip6, "fd00:01::1") == 0) return 1;
    if (strcmp(ip6, "fd00:1::1") == 0) return 1;
    if (strcmp(ip6, "fd00:01::2") == 0) return 10;
    if (strcmp(ip6, "fd00:1::2") == 0) return 10;
    if (strcmp(ip6, "fd00:12::1") == 0) return 20;
    if (strcmp(ip6, "fd00:12::2") == 0) return 30;
    if (strcmp(ip6, "fd00:23::2") == 0) return 40;
    if (strcmp(ip6, "fd00:23::3") == 0) return 50;
    if (strcmp(ip6, "fd00:23::4") == 0) return 60;
    if (strcmp(ip6, "fd00:23::5") == 0) return 70;
    return -1;
}

int nodeid_to_ipv6(long node_id, ip6_addr_t *out) {

    const char *addr_txt = NULL;
    switch (node_id) {
        /*
        case 1: addr_txt = "fd00:01::1"; break;
        case 10: addr_txt = "fd00:01::2"; break;
        case 12: addr_txt = "fd00:12::1"; break;
        case 21: addr_txt = "fd00:12::2"; break;
        case 23: addr_txt = "fd00:23::2"; break;
        case 32: addr_txt = "fd00:23::3"; break;
        */
        case 1: addr_txt = "fd00:01::1"; break;
        case 10: addr_txt = "fd00:01::2"; break;
        case 20: addr_txt = "fd00:12::1"; break;
        case 30: addr_txt = "fd00:12::2"; break;
        case 40: addr_txt = "fd00:23::2"; break;
        case 50: addr_txt = "fd00:23::3"; break;
        case 60: addr_txt = "fd00:23::4"; break;
        case 70: addr_txt = "fd00:23::5"; break;

        default: return -1;
    }

    unsigned char tmpbuf[16];
    if (inet_pton(AF_INET6, addr_txt, tmpbuf) != 1) {
        return -1;
    }

    for (int i = 0; i < 4; ++i) {
        uint32_t w = (tmpbuf[i*4 + 0] << 24) |
                     (tmpbuf[i*4 + 1] << 16) |
                     (tmpbuf[i*4 + 2] << 8 ) |
                     (tmpbuf[i*4 + 3] << 0 );
        out->addr[i] = ntohl(w);
    }
    return 0;
}

int main(void) {
    u32_t _v_tc_fl = 0x60000000;     // version(4) + traffic class(8) + flow label(20) 
    u16_t _plen = 10;               // payload length 
    u8_t  _hoplim = 64;              // hop limit -> lifetime 
    ip6_addr_t local;                // current node
    ip6_addr_t dest;                 // destination of the pkt

    unsigned char tmpbuf[16];

    if (inet_pton(AF_INET6, "fd00:01::1", tmpbuf) != 1) {
        fprintf(stderr, "inet_pton local address failed\n");
        return 1;
    }
    for (int i=0;i<4;i++) {
        uint32_t w = (tmpbuf[i*4+0] << 24) | (tmpbuf[i*4+1] << 16) | (tmpbuf[i*4+2] << 8) | (tmpbuf[i*4+3]);
        local.addr[i] = ntohl(w);
    }

    if (inet_pton(AF_INET6, "fd00:23::5", tmpbuf) != 1) {
        fprintf(stderr, "inet_pton dest failed\n");
        return 1;
    }
    for (int i=0;i<4;i++) {
        uint32_t w = (tmpbuf[i*4+0] << 24) | (tmpbuf[i*4+1] << 16) | (tmpbuf[i*4+2] << 8) | (tmpbuf[i*4+3]);
        dest.addr[i] = ntohl(w);
    }

    //conver address to string to print
    char curr_node_s[INET6_ADDRSTRLEN], dst_s[INET6_ADDRSTRLEN]; 

    if (ip6_addr_to_str(&local, curr_node_s, sizeof(curr_node_s)) != 0) { 
        fprintf(stderr, "ip6_addr_to_str local address failed\n"); return 1;
    } 
    
    if (ip6_addr_to_str(&dest, dst_s, sizeof(dst_s)) != 0) { 
        fprintf(stderr, "ip6_addr_to_str dest failed\n"); return 1; 
    }

    printf("local: %s\n", curr_node_s);
    printf("dst: %s\n", dst_s);

    //python initialize
    Py_Initialize();

    PyObject *sys_path = PySys_GetObject("path");
    PyObject *py_pth = PyUnicode_FromString("."); 
    PyList_Append(sys_path, py_pth);
    Py_DECREF(py_pth);

    PyObject *pModule = PyImport_ImportModule("py_cgr_lib.py_cgr_lib");

    PyObject *py_cp_load = PyObject_GetAttrString(pModule, "cp_load");
    PyObject *py_cgr_yen = PyObject_GetAttrString(pModule, "cgr_yen");
    PyObject *py_fwd_candidate = PyObject_GetAttrString(pModule, "fwd_candidate");
    PyObject *py_ipv6_packet = PyObject_GetAttrString(pModule, "ipv6_packet");

    // cp_load
    PyObject *args_load = PyTuple_New(2);
    PyTuple_SetItem(args_load, 0, PyUnicode_FromString("contact_plans/cgr_tutorial_4.txt"));
    PyTuple_SetItem(args_load, 1, PyLong_FromLong(5000));
    PyObject *contact_plan = PyObject_CallObject(py_cp_load, args_load);
    PyObject *repr_cp = PyObject_Repr(contact_plan);
    if (repr_cp) {
        const char *s = PyUnicode_AsUTF8(repr_cp);
        fprintf(stderr, "[DBG] contact_plan repr: %s\n", s ? s : "<NULL>");
        Py_DECREF(repr_cp);
    } else {
        fprintf(stderr, "[DBG] contact_plan repr failed\n");
        PyErr_Print();
    }
    Py_DECREF(args_load);

    // cgr_yen
    long curr_node_id = ipv6_to_nodeid(curr_node_s);
    long dest_node_id   = ipv6_to_nodeid(dst_s);

    double curr_time = 0; //the reference time is 0
    PyObject *args_yen = PyTuple_New(5);
    PyTuple_SetItem(args_yen, 0, PyLong_FromLong(curr_node_id));
    PyTuple_SetItem(args_yen, 1, PyLong_FromLong(dest_node_id));
    PyTuple_SetItem(args_yen, 2, PyFloat_FromDouble(curr_time));
    PyTuple_SetItem(args_yen, 3, contact_plan);
    PyTuple_SetItem(args_yen, 4, PyLong_FromLong(10)); 
    PyObject *routes = PyObject_CallObject(py_cgr_yen, args_yen);
    PyObject *repr_r = PyObject_Repr(routes);
    if (repr_r) {
        const char *sr = PyUnicode_AsUTF8(repr_r);
        fprintf(stderr, "[DBG] routes repr: %s\n", sr ? sr : "<NULL>");
        Py_DECREF(repr_r);
    } else {
        fprintf(stderr, "[DBG] routes repr failed\n");
        PyErr_Print();
    }
    if (PyList_Check(routes)) {
        fprintf(stderr, "[DBG] routes length: %ld\n", PyList_Size(routes));
    } else {
        fprintf(stderr, "[DBG] routes is not a list (type=%s)\n", routes->ob_type->tp_name);
    }
    Py_DECREF(args_yen);

    // ipv6_packet
    long size = _plen;
    long deadline = _hoplim*10; //multiplying factor to transform to lifetime
    uint8_t tc = (uint8_t)((_v_tc_fl >> 20) & 0xFF); // traffic class (8 bits) 
    uint8_t dscp = (uint8_t)(tc >> 2);               // DSCP = TC[7:2] (6 bits)

    PyObject *args_pkt = PyTuple_New(4);
    PyTuple_SetItem(args_pkt, 0, PyLong_FromLong(dest_node_id));
    PyTuple_SetItem(args_pkt, 1, PyLong_FromLong(size));
    PyTuple_SetItem(args_pkt, 2, PyLong_FromLong(deadline));
    PyTuple_SetItem(args_pkt, 3, PyLong_FromLong(dscp));
    PyObject *ipv6pkt = PyObject_CallObject(py_ipv6_packet, args_pkt);
    Py_DECREF(args_pkt);

    /* ------------------ fwd_candidate ------------------ */
    PyObject *excluded_nodes = PyList_New(0);
    PyObject *args_fwd = PyTuple_New(6);
    PyTuple_SetItem(args_fwd, 0, PyFloat_FromDouble(curr_time));
    PyTuple_SetItem(args_fwd, 1, PyLong_FromLong(curr_node_id));
    PyTuple_SetItem(args_fwd, 2, contact_plan);
    PyTuple_SetItem(args_fwd, 3, ipv6pkt);
    PyTuple_SetItem(args_fwd, 4, routes);
    PyTuple_SetItem(args_fwd, 5, excluded_nodes);
    PyObject *candidates = PyObject_CallObject(py_fwd_candidate, args_fwd);
    if (candidates) {
    PyObject *repr_c = PyObject_Repr(candidates);
    const char *sc = PyUnicode_AsUTF8(repr_c);
    fprintf(stderr, "[DBG] candidates repr: %s\n", sc? sc : "<NULL>");
    Py_XDECREF(repr_c);
        if (PyList_Check(candidates)) {
            long n = PyList_Size(candidates);
            fprintf(stderr, "[DBG] candidates length: %ld\n", n);
            for (long i = 0; i < n; ++i) {
                PyObject *it = PyList_GetItem(candidates, i);
                PyObject *repr_it = PyObject_Repr(it);
                const char *si = PyUnicode_AsUTF8(repr_it);
                fprintf(stderr, "[DBG] candidate[%ld] repr: %s\n", i, si? si : "<NULL>");
                Py_XDECREF(repr_it);

                // try to print next_node attr if present
                PyObject *pNextNode = PyObject_GetAttrString(it, "next_node");
                if (pNextNode) {
                    if (pNextNode == Py_None) {
                        fprintf(stderr, "[DBG] candidate[%ld] next_node = None\n", i);
                    } else if (PyLong_Check(pNextNode)) {
                        fprintf(stderr, "[DBG] candidate[%ld] next_node = %ld\n", i, PyLong_AsLong(pNextNode));
                    } else {
                        fprintf(stderr, "[DBG] candidate[%ld] next_node has non-int type (%s)\n", i, pNextNode->ob_type->tp_name);
                    }
                    Py_DECREF(pNextNode);
                } else {
                    PyErr_Clear();
                    fprintf(stderr, "[DBG] candidate[%ld] has no next_node\n", i);
                }
            }
        } else {
            fprintf(stderr, "[DBG] candidates is not a list (type=%s)\n", candidates->ob_type->tp_name);
        }
    } else {
        fprintf(stderr, "[DBG] candidates is NULL\n");
        PyErr_Print();
    }
    Py_DECREF(args_fwd);

    //we check the next hop for the best route
    if (PyList_Check(candidates) && PyList_Size(candidates) > 0) {
        PyObject *first = PyList_GetItem(candidates, 0); /* borrowed reference */
        PyObject *pNextNode = PyObject_GetAttrString(first, "next_node"); /* new ref or NULL */
        if (pNextNode) {
            if (pNextNode == Py_None) {
                printf("Next hop: None\n");
            } else if (PyLong_Check(pNextNode)) {
                long next_node = PyLong_AsLong(pNextNode);
                ip6_addr_t next_ip;
                if (nodeid_to_ipv6(next_node, &next_ip) == 0) {
                    //printf("Next hop node: %ld\n", next_node);
                    char next_ip_s[INET6_ADDRSTRLEN];
                    if (ip6_addr_to_str(&next_ip, next_ip_s, sizeof(next_ip_s)) == 0) {
                        printf("Next hop ipv6: %s\n", next_ip_s);
                    } else {
                        fprintf(stderr, "Failed to stringify next_ip for node %ld\n", next_node);
                    }
                } else {
                    fprintf(stderr, "No mapping nodeid->ipv6 for node %ld\n", next_node);
                }

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
    Py_DECREF(pModule);
    Py_Finalize();
    return 0;
}