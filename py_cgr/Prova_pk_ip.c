#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <string.h>
#include <time.h>
#include <ctype.h>

/* Tipus reinclosos del teu codi */
typedef uint32_t u32_t;
typedef uint16_t u16_t;
typedef uint8_t  u8_t;

struct ip6_addr {
    u32_t addr[4];
    // u8_t zone; // no considerem zone aquí
};
typedef struct ip6_addr ip6_addr_t;

/* Converteix ip6_addr_t a string textual IPv6 */
int ip6_addr_to_str(const ip6_addr_t *a, char *buf, size_t buflen) {
    if (!a || !buf) return -1;
    unsigned char tmp[16];
    for (int i = 0; i < 4; ++i) {
        /* assumim que a->addr[i] està en host order; posem en network order per a inet_ntop */
        uint32_t w = htonl(a->addr[i]);
        tmp[i*4 + 0] = (w >> 24) & 0xFF;
        tmp[i*4 + 1] = (w >> 16) & 0xFF;
        tmp[i*4 + 2] = (w >> 8 ) & 0xFF;
        tmp[i*4 + 3] = (w >> 0 ) & 0xFF;
    }
    if (!inet_ntop(AF_INET6, tmp, buf, (socklen_t)buflen)) return -1;
    return 0;
}

/* Heurística simple per mapar textual IPv6 -> node id (int)
   - Si l'adreça comença per "fd00::", pren el sufix i interpreta'l com hex o decimal.
   - Ex: fd00::1 -> 1; fd00::A -> 10
   - Si no coincideix, retorna -1 (mapping failed).
   Pots substituir aquesta funció per llegir un fitxer de mapatge o taula. */
long ipv6_to_nodeid_heuristic(const char *ip6) {
    if (!ip6) return -1;
    const char *p = NULL;
    /* busquem el prefix "fd00::" o "fd00:" */
    if (strncmp(ip6, "fd00::", 6) == 0) p = ip6 + 6;
    else if (strncmp(ip6, "fd00:", 5) == 0) p = ip6 + 5;
    else return -1;

    if (*p == '\0') return -1;

    /* p apunta al sufix; acceptem números hex o decimal.
       Remove possible scope or brackets (rare) */
    char clean[64];
    size_t j = 0;
    for (size_t i = 0; p[i] && j+1 < sizeof(clean); ++i) {
        char c = p[i];
        if (c == '%') break; /* zone index */
        if (c == ']') break;
        if (c == '/') break;
        if (c == ':') break; /* if there is further hextets, bail */
        if (!isspace((unsigned char)c)) clean[j++] = c;
    }
    clean[j] = '\0';
    if (j == 0) return -1;

    /* try as hex first if contains hex letters, else decimal */
    int is_hex = 0;
    for (size_t i=0;i<j;i++) {
        if ((clean[i] >= 'a' && clean[i] <= 'f') || (clean[i] >= 'A' && clean[i] <= 'F')) {
            is_hex = 1; break;
        }
    }
    char *endptr = NULL;
    long val = 0;
    if (is_hex) {
        val = strtol(clean, &endptr, 16);
    } else {
        val = strtol(clean, &endptr, 10);
    }
    if (endptr == clean) return -1;
    return val;
}

int main(void) {
    /* ------------------ Definicions/vars com les teves ------------------ */
    u32_t _v_tc_fl = 0x60000000;     /* version(4) + traffic class(8) + flow label(20) */
    u16_t _plen = 200;               /* payload length */
    u8_t  _hoplim = 64;              /* hop limit -> lifetime */
    ip6_addr_t src;
    ip6_addr_t dest;

    /* Inicialitzem adreces d'exemple (host-order storage) */
    memset(&src, 0, sizeof(src));
    memset(&dest, 0, sizeof(dest));
    unsigned char tmpbuf[16];

    if (inet_pton(AF_INET6, "fd00::1", tmpbuf) != 1) {
        fprintf(stderr, "inet_pton src failed\n");
        return 1;
    }
    /* guardem en quatre words (host order) */
    for (int i=0;i<4;i++) {
        uint32_t w = (tmpbuf[i*4+0] << 24) | (tmpbuf[i*4+1] << 16) | (tmpbuf[i*4+2] << 8) | (tmpbuf[i*4+3]);
        src.addr[i] = ntohl(w);
    }

    if (inet_pton(AF_INET6, "fd00::5", tmpbuf) != 1) {
        fprintf(stderr, "inet_pton dest failed\n");
        return 1;
    }
    for (int i=0;i<4;i++) {
        uint32_t w = (tmpbuf[i*4+0] << 24) | (tmpbuf[i*4+1] << 16) | (tmpbuf[i*4+2] << 8) | (tmpbuf[i*4+3]);
        dest.addr[i] = ntohl(w);
    }

    /* Convertim adreces a text per passar a Python i per fer mapping */
    char src_s[INET6_ADDRSTRLEN], dst_s[INET6_ADDRSTRLEN];
    if (ip6_addr_to_str(&src, src_s, sizeof(src_s)) != 0) {
        fprintf(stderr, "ip6_addr_to_str src failed\n");
        return 1;
    }
    if (ip6_addr_to_str(&dest, dst_s, sizeof(dst_s)) != 0) {
        fprintf(stderr, "ip6_addr_to_str dest failed\n");
        return 1;
    }

    printf("src textual: %s\n", src_s);
    printf("dst textual: %s\n", dst_s);
    printf("size(_plen)=%u hoplim=%u\n", _plen, _hoplim);

    /* ------------------ inicialitzem Python embegit ------------------ */
    Py_Initialize();
    if (!Py_IsInitialized()) {
        fprintf(stderr, "Python not initialized\n");
        return 1;
    }

    /* Afegim directori actual al sys.path perquè puguem importar py_cgr_lib package */
    PyObject *sys_path = PySys_GetObject("path");
    PyObject *py_pth = PyUnicode_FromString("."); 
    PyList_Append(sys_path, py_pth);
    Py_DECREF(py_pth);

    /* Importem el mòdul py_cgr_lib.py_cgr_lib */
    PyObject *pModule = PyImport_ImportModule("py_cgr_lib.py_cgr_lib");
    if (!pModule) {
        PyErr_Print();
        fprintf(stderr, "ERROR: cannot import py_cgr_lib.py_cgr_lib\n");
        Py_Finalize();
        return 1;
    }

    /* Obtenim referències a les funcions/classe */
    PyObject *py_cp_load = PyObject_GetAttrString(pModule, "cp_load");
    PyObject *py_cgr_yen = PyObject_GetAttrString(pModule, "cgr_yen");
    PyObject *py_fwd_candidate = PyObject_GetAttrString(pModule, "fwd_candidate");
    PyObject *py_ipv6_packet_cls = PyObject_GetAttrString(pModule, "ipv6_packet");

    if (!py_cp_load || !py_cgr_yen || !py_fwd_candidate || !py_ipv6_packet_cls) {
        PyErr_Print();
        fprintf(stderr, "ERROR: missing attribute(s) in py_cgr_lib\n");
        goto py_cleanup_module;
    }

    /* ------------------ cridem cp_load ------------------ */
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
    /* imprimim nombre de contacts (len) si és llista */
    if (PyList_Check(contact_plan)) {
        long n = PyList_Size(contact_plan);
        printf("Loaded contacts: %ld\n", n);
    } else {
        printf("cp_load returned non-list (proceeding)\n");
    }

    /* ------------------ cridem cgr_yen ------------------ */
    long source_node = ipv6_to_nodeid_heuristic(src_s);
    long dest_node   = ipv6_to_nodeid_heuristic(dst_s);
    if (source_node < 0 || dest_node < 0) {
        fprintf(stderr, "Mapping IPv6->node failed: src=%ld dst=%ld\n", source_node, dest_node);
        goto py_cleanup_contact_plan;
    }

    double curr_time = (double)time(NULL);
    PyObject *args_yen = PyTuple_New(5);
    PyTuple_SetItem(args_yen, 0, PyLong_FromLong(source_node));
    PyTuple_SetItem(args_yen, 1, PyLong_FromLong(dest_node));
    PyTuple_SetItem(args_yen, 2, PyFloat_FromDouble(curr_time));
    PyTuple_SetItem(args_yen, 3, contact_plan); /* transfers ref to tuple */
    PyTuple_SetItem(args_yen, 4, PyLong_FromLong(10)); /* num_routes */
    PyObject *routes = PyObject_CallObject(py_cgr_yen, args_yen);
    Py_DECREF(args_yen);
    if (!routes) {
        PyErr_Print();
        fprintf(stderr, "ERROR: cgr_yen failed\n");
        goto py_cleanup_contact_plan;
    }

    /* ------------------ crea ipv6_packet(dst, size, deadline, priority) ------------------ */
    long size = _plen;
    long deadline = (long)6000000; 
    uint8_t tc = (uint8_t)((_v_tc_fl >> 20) & 0xFF); /* traffic class (8 bits) */
    uint8_t dscp = (uint8_t)(tc >> 2);              /* DSCP = TC[7:2] (6 bits) */

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

    /* ------------------ cridem fwd_candidate(curr_time, source, contact_plan, ipv6_pkt, routes, excluded_nodes) ------------------ */
    PyObject *excluded_nodes = PyList_New(0);
    PyObject *args_fwd = PyTuple_New(6);
    PyTuple_SetItem(args_fwd, 0, PyFloat_FromDouble(curr_time));
    PyTuple_SetItem(args_fwd, 1, PyLong_FromLong(source_node));
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

    /* ------------------ llegim candidate[0].next_node ------------------ */
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

    /* neteja */
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