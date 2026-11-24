"""Inicia o uvicorn num socket dual-stack (IPv6 + IPv4 na mesma porta).

A rede Docker `echelon` resolve os contêineres primeiro em IPv6; com o uvicorn ouvindo só IPv4, o
Nginx Proxy Manager tomava um 502 e repetia a requisição em IPv4. O asyncio cria sockets "::" como
somente IPv6, por isso o socket é criado aqui com IPV6_V6ONLY=0 e entregue pronto ao uvicorn.
"""
import os
import socket

import uvicorn


def _socket(porta: int) -> socket.socket:
    try:
        sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        endereco = ("::", porta)
    except OSError:  # host sem IPv6: só IPv4
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        endereco = ("0.0.0.0", porta)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(endereco)
    sock.set_inheritable(True)
    return sock


if __name__ == "__main__":
    porta = int(os.getenv("PORT", "8000"))
    config = uvicorn.Config("app:app", proxy_headers=False, log_level="info")
    uvicorn.Server(config).run(sockets=[_socket(porta)])
