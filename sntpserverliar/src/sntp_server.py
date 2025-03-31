import socket
import datetime
import struct
import time
import yaml

LISTEN_IP = "0.0.0.0"
LISTEN_PORT = 123
BUFFER_SIZE = 1024
NTP_EPOCH = datetime.datetime(1900, 1, 1)
NTP_EPOCH_DELTA = 2208988800
SNTP_PACKET_FORMAT = '! B B b b I I 4s II II II II'


def parse_sntp_request(data):
    if len(data) < 48:
        print("Ошибка: Cлишком короткий пакет, игнорируется.")
        return
    unpacked_data = struct.unpack(SNTP_PACKET_FORMAT, data[:48])
    li_vn_mode_header_byte = unpacked_data[0]
    version = (li_vn_mode_header_byte >> 3) & 0x07
    mode = li_vn_mode_header_byte & 0x07

    client_transmit_sec = unpacked_data[13]
    client_transmit_frac = unpacked_data[14]

    if mode != 3:
        print(f"Неверный режим запроса {mode}")

    print(f"Пакет: VN={version}, Mode={mode}, Client ={client_transmit_sec}.{client_transmit_frac}")

    return version, client_transmit_sec, client_transmit_frac


def time_with_offset(time_offset):
    current_time = time.time() + time_offset
    print(f"OS time: {time.time()}, Adjusted: {current_time}")
    ntp_sec = int(current_time) + NTP_EPOCH_DELTA
    ntp_frac = int(abs(current_time - int(current_time)) * 2 ** 32)
    return ntp_sec, ntp_frac


def read_config(config_file="config.yaml"):
    try:
        with open(config_file, 'r') as file:
            config = yaml.safe_load(file)

        if config is None or 'Settings' not in config:
            print("Settings не найдены в файле конфигурации")
            return 0

        if 'time_offset' in config['Settings']:
            time_offset = int(config['Settings']['time_offset'])
            print(f"Смещение времени {time_offset}")
            return time_offset
        else:
            print("Не найдена настройка смещения времени, используется по умолчанию 0")
            return 0
    except Exception as e:
        print(f"Ошибка при чтении конфигурации: {e}, смещение по времени 0")
        return 0


def get_sntp_response(version, offset, orig_transmit_sec, orig_transmit_frac):
    recv_ts_sec, recv_ts_frac = time_with_offset(offset)
    transm_sec, transm_frac = time_with_offset(offset)

    li_vn_mode = (0 << 6) | (version << 3) | 4
    stratum = 2
    poll = 10
    precision = -20
    root_delay = 0
    root_dispersion = 0
    ref_id = b'LIES'
    ref_ts_sec, ref_ts_frac = 0, 0
    packed_response = struct.pack(
        SNTP_PACKET_FORMAT,
        li_vn_mode, stratum, poll, precision, root_delay, root_dispersion, ref_id,
        ref_ts_sec, ref_ts_frac,
        orig_transmit_sec, orig_transmit_frac,
        recv_ts_sec, recv_ts_frac,
        transm_sec, transm_frac
    )
    return packed_response


def run_server():
    try:
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        print(f"Сокет успешно создан.")
        server_socket.bind((LISTEN_IP, LISTEN_PORT))
        print(f"Сервер слушает на {LISTEN_IP}:{LISTEN_PORT}")
    except socket.error as e:
        print(f"Ошибка при создании или привязке сокета: {e}")
        return

    print("Сервер запущен и ожидает запросы...")
    offset = read_config()
    try:
        while True:
            print("\nОжидание следующего пакета...")
            try:
                data, addr = server_socket.recvfrom(BUFFER_SIZE)
                print(f"Получен пакет от {addr[0]}:{addr[1]} ({len(data)} байт)")
                print(f"Полученны данные (байты): {data!r}")
                version, orig_transmit_sec, orig_transmit_frac = parse_sntp_request(data)
                packed_response = get_sntp_response(version, offset, orig_transmit_sec, orig_transmit_frac)
                server_socket.sendto(packed_response, addr)
                print(orig_transmit_sec)
                print(time.time())
                print(f"Отправлен SNTP ответ ({len(packed_response)} байт) клиенту {addr}")

            except socket.error as e:
                print(f"Сетевая ошибка при приеме/отправке: {e}")
            except Exception as e:
                print(f"Произошла непредвиденная ошибка: {e}")

    except KeyboardInterrupt:
        print("\nСервер останавливается по команде пользователя (Ctrl+C).")
    finally:
        server_socket.close()
        print("Сокет закрыт. Завершение работы.")


if __name__ == "__main__":
    run_server()
