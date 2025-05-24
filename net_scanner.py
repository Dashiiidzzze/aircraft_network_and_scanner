import argparse
import sys
import os
import re
import docker
import yaml
from typing import Dict, List, Tuple, Set
import nmap
from typing import Set, Tuple

# Константы
CRITICAL_SERVICES = ["sensors", "controllers", "actuators", "pilot_interface", "avionics"]
INFO_SERVICES = ["crew_communication", "secure_gateway"]
GATEWAY_SERVICES = ["firewall"]
ALL_SERVICES = CRITICAL_SERVICES + GATEWAY_SERVICES + INFO_SERVICES

EXPECTED_NETWORKS = [
    "critical_internal", 
    "info_internal"
]

# Настройки таймаутов
CONNECTION_TIMEOUT = 2  # секунды
UDP_TEST_TIMEOUT = 1  # секунды

# Небезопасные базовые образы
INSECURE_BASE_IMAGES = [
    'ubuntu:latest',
    'debian:latest',
    'centos:latest',
    'alpine:latest',
    'node:latest',
    'python:latest',
    'nginx:latest'
]

# Небезопасные команды в Dockerfile
INSECURE_DOCKERFILE_PATTERNS = [
    (r'RUN\s+.*wget.*http://', "Использование небезопасного HTTP для загрузки"),
    (r'RUN\s+.*curl.*http://', "Использование небезопасного HTTP для загрузки"),
    (r'ADD\s+http://', "Использование небезопасного HTTP в ADD"),
    (r'RUN\s+.*sudo', "Использование sudo в контейнере"),
    (r'RUN\s+.*su\s+', "Использование su в контейнере"),
    (r'RUN\s+.*chmod\s+777', "Установка небезопасных прав доступа 777"),
    (r'RUN\s+.*chmod\s+\+x\s+/.*', "Широкие права на исполнение"),
    (r'COPY\s+.*\s+/', "Копирование в корневую директорию"),
    (r'ADD\s+.*\.tar\.gz\s+/', "Распаковка архивов в корневую директорию"),
    (r'RUN\s+.*pip\s+install.*--trusted-host', "Установка пакетов из недоверенных источников"),
    (r'RUN\s+.*npm\s+install.*--unsafe-perm', "Небезопасная установка npm пакетов"),
]

# Цвета для вывода
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


class Vulnerability_scanner:
    # конструктор класса
    def __init__(self, compose_file: str, verbose: bool = False):
        self.compose_file = compose_file                # Сохраняем путь к docker-compose файлу
        self.verbose = verbose                          # Флаг для подробного вывода
        self.vulnerabilities = []                       # Список, куда будут добавляться найденные уязвимости
        self.docker_client = docker.from_env()          # Создаём клиент Docker API
        self.network_map = {}                           # Сопоставление сетей -> сервисы
        self.service_configs = {}                       # Конфигурации сервисов из compose-файла
        self.services_running = set()                   # Множество запущенных контейнеров (по именам)
        self.dockerfile_paths = {}                      # Пути к Dockerfile'ам для каждого сервиса

        self.load_compose_file()                        # Загружаем и парсим docker-compose.yml
        self.map_networks()                             # Формируем сетевую карту сервисов
        self.find_dockerfiles()                         # Находим Dockerfile'ы для сервисов

    # Загружает и анализирует docker-compose файл
    def load_compose_file(self) -> None:
        try:
            with open(self.compose_file, 'r') as f:
                self.compose_config = yaml.safe_load(f) 
                
            if 'services' not in self.compose_config:
                self.log_error("Файл docker-compose не содержит раздел 'services'")
                sys.exit(1)
                
            self.service_configs = self.compose_config['services']
            self.log_info(f"Загружена конфигурация docker-compose с {len(self.service_configs)} сервисами")
        except Exception as e:
            self.log_error(f"Ошибка при загрузке docker-compose файла: {str(e)}")
            sys.exit(1)
    
    # Находит Dockerfile'ы для каждого сервиса
    def find_dockerfiles(self) -> None:
        base_dir = os.path.dirname(os.path.abspath(self.compose_file))
        
        for service_name, service_config in self.service_configs.items():
            dockerfile_path = None
            
            # Проверяем build context
            build_config = service_config.get('build', {})
            if isinstance(build_config, str):
                # build: ./path
                context_path = os.path.join(base_dir, build_config)
                dockerfile_path = os.path.join(context_path, 'Dockerfile')
            elif isinstance(build_config, dict):
                # build:
                #   context: ./path
                #   dockerfile: CustomDockerfile
                context = build_config.get('context', '.')
                dockerfile = build_config.get('dockerfile', 'Dockerfile')
                context_path = os.path.join(base_dir, context)
                dockerfile_path = os.path.join(context_path, dockerfile)
            
            if dockerfile_path and os.path.isfile(dockerfile_path):
                self.dockerfile_paths[service_name] = dockerfile_path
                self.log_info(f"Найден Dockerfile для {service_name}: {dockerfile_path}")
            else:
                self.log_info(f"Dockerfile не найден для {service_name} (используется готовый образ)")

    # Сопоставляет сервисы с сетями из docker-compose файла
    def map_networks(self) -> None:
        networks_section = self.compose_config.get('networks', {})
        
        # Проверка существования ожидаемых сетей
        for network in EXPECTED_NETWORKS:
            if network not in networks_section:
                self.add_vulnerability(
                    "Network Configuration", 
                    f"Ожидаемая сеть {network} не объявлена в конфигурации",
                    "HIGH"
                )
        
        # Создаем карту сервисов и их сетей
        for service_name, service_config in self.service_configs.items():
            networks = service_config.get('networks', {})
            
            if isinstance(networks, list):
                service_networks = networks
            elif isinstance(networks, dict):
                service_networks = list(networks.keys())
            else:
                service_networks = []
                
            for network in service_networks:
                if network not in self.network_map:
                    self.network_map[network] = []
                self.network_map[network].append(service_name)
        
        self.log_info(f"Сопоставлены сервисы с {len(self.network_map)} сетями")
    
    # добавляет найденную уязвимость в список
    def add_vulnerability(self, component: str, description: str, severity: str) -> None:
        vulnerability = {
            "component": component,
            "description": description,
            "severity": severity
        }
        self.vulnerabilities.append(vulnerability)
        
        # Вывод уязвимости сразу при обнаружении
        severity_color = Colors.WARNING if severity == "MEDIUM" else \
                          Colors.FAIL if severity == "HIGH" else \
                          Colors.BLUE
        
        print(f"{severity_color}[{severity}]{Colors.ENDC} {Colors.BOLD}{component}:{Colors.ENDC} {description}")
    
    # Запускает полное сканирование всех компонентов системы
    def scan_all(self) -> None:
        self.log_header("НАЧАЛО СКАНИРОВАНИЯ УЯЗВИМОСТЕЙ БОРТОВОЙ СЕТИ")
        
        # # Проверка запущенных сервисов
        self.check_running_services()
        
        # # Сканирование конфигурационных файлов
        self.scan_config_files()
        
        # # Сканирование Dockerfile'ов
        self.scan_dockerfiles()
        
        # # Сканирование сетевой топологии
        self.scan_network_topology()
        
        # # Сканирование уязвимостей в контейнерах
        self.scan_container_vulnerabilities()
        
        # # Сканирование портов
        self.scan_open_ports()
        
        # # Проверка защищенности коммуникаций
        self.check_secure_communications()
        
        # # Проверка разделения сетей
        self.check_network_segregation()
        
        # # Проверка секретов и переменных окружения
        self.check_secrets_and_env()
        
        self.log_header("ЗАВЕРШЕНО СКАНИРОВАНИЕ УЯЗВИМОСТЕЙ")
        self.print_summary()

    # Проверяет какие сервисы запущены
    def check_running_services(self) -> None:
        self.log_info("Проверка запущенных сервисов...")
        try:
            # Получаем все запущенные контейнеры
            containers = self.docker_client.containers.list()
            
            for container in containers:
                # Пытаемся извлечь имя сервиса из метки, которую Docker Compose автоматически добавляет
                service_name = container.labels.get('com.docker.compose.service')
                
                if service_name:
                    self.services_running.add(service_name)
                    if self.verbose:
                        print(f"{Colors.CYAN}[INFO]{Colors.ENDC} Обнаружен запущенный сервис: {service_name}")
                else:
                    # Метка отсутствует — возможно, контейнер не создан через docker-compose
                    self.log_warning(f"Контейнер без метки 'com.docker.compose.service': {container.name}")
            
            # Сравниваем с ожидаемыми сервисами
            for service in ALL_SERVICES:
                if service not in self.services_running:
                    self.add_vulnerability(
                        service,
                        "Сервис не запущен, но требуется для правильной работы системы",
                        "HIGH"
                    )
        
        except Exception as e:
            self.log_error(f"Ошибка при проверке запущенных сервисов: {str(e)}")

    # Сканирует конфигурационный файл docker-compose на предмет уязвимостей
    def scan_config_files(self) -> None:
        self.log_info("Сканирование конфигурации docker-compose...")
        
        # Проверка сервиса sensors
        sensors_config = self.service_configs.get('sensors', {})
        if not sensors_config.get('read_only', False):
            self.add_vulnerability(
                "sensors", 
                "Контейнер сенсоров не настроен как read-only, что повышает риск модификации критического компонента",
                "HIGH"
            )
        
        # Проверка настроек restart для критических сервисов
        for service in CRITICAL_SERVICES:
            config = self.service_configs.get(service, {})
            if config.get('restart') != 'always':
                self.add_vulnerability(
                    service, 
                    "Отсутствует политика автоматического перезапуска (restart: always) для критического сервиса",
                    "MEDIUM"
                )
            
            # Проверка параметра no-new-privileges
            security_opts = config.get('security_opt', [])
            has_no_new_privileges = any('no-new-privileges:true' in opt for opt in security_opts)
            if not has_no_new_privileges:
                self.add_vulnerability(
                    service, 
                    "Отсутствует ограничение no-new-privileges, что позволяет эскалацию привилегий",
                    "HIGH"
                )
            
            # Проверка понижения привилегий через cap_drop
            cap_drop = config.get('cap_drop', [])
            if 'ALL' not in cap_drop:
                self.add_vulnerability(
                    service, 
                    "Не применено понижение всех возможностей (cap_drop: [ALL]), что повышает риск эксплуатации уязвимостей",
                    "HIGH"
                )
        
        # Проверка наличия UDP_SECRET_KEY в переменных окружения
        for service in ["sensors", "controllers", "actuators", "pilot_interface", "avionics"]:
            config = self.service_configs.get(service, {})
            env_vars = config.get('environment', [])
            
            has_udp_key = False
            for env in env_vars:
                if isinstance(env, str) and env.startswith('UDP_SECRET_KEY='):
                    has_udp_key = True
                    break
            
            if not has_udp_key:
                self.add_vulnerability(
                    service, 
                    "Отсутствует или неправильно настроен ключ шифрования UDP_SECRET_KEY для защищенной коммуникации",
                    "HIGH"
                )
        
        # Проверка настроек healthcheck для всех сервисов
        for service_name, config in self.service_configs.items():
            if service_name in ALL_SERVICES and 'healthcheck' not in config:
                self.add_vulnerability(
                    service_name, 
                    "Отсутствует healthcheck, что может привести к работе неисправного сервиса",
                    "MEDIUM"
                )
        
        # Проверка наличия параметров сертификатов для https сервисов
        https_services = ["controllers", "pilot_interface", "avionics", "secure_gateway", "crew_communication"]
        for service in https_services:
            config = self.service_configs.get(service, {})
            env_vars = config.get('environment', [])
            
            cert_vars = set()
            for env in env_vars:
                if isinstance(env, str):
                    if env.startswith('CERT_PATH='):
                        cert_vars.add('CERT_PATH')
                    elif env.startswith('KEY_PATH='):
                        cert_vars.add('KEY_PATH')
                    elif env.startswith('CA_PATH='):
                        cert_vars.add('CA_PATH')
            
            if len(cert_vars) < 3:
                self.add_vulnerability(
                    service, 
                    f"Неполная конфигурация HTTPS: отсутствуют некоторые переменные для сертификатов. Найдено: {', '.join(cert_vars)}",
                    "HIGH"
                )
            
            # Проверка монтирования сертификатов
            volumes = config.get('volumes', [])
            has_certs_volume = any('/certs:' in vol for vol in volumes)
            if not has_certs_volume:
                self.add_vulnerability(
                    service, 
                    "Отсутствует монтирование сертификатов, необходимых для HTTPS",
                    "HIGH"
                )
        
        # Проверка корректности указания внутренних (internal) сетей
        networks = self.compose_config.get('networks', {})
        for network_name, network_config in networks.items():
            if network_name in ['critical_internal', 'info_internal']:
                if not network_config.get('internal', False):
                    self.add_vulnerability(
                        f"Network {network_name}", 
                        "Внутренняя сеть не настроена как internal: true, что может позволить внешний доступ",
                        "HIGH"
                    )

    # сканирование Dockerfile'ов
    def scan_dockerfiles(self) -> None:
        self.log_info("Сканирование Dockerfile'ов на уязвимости...")
        
        for service_name, dockerfile_path in self.dockerfile_paths.items():
            self.log_info(f"Анализ Dockerfile для сервиса {service_name}")
            
            try:
                with open(dockerfile_path, 'r', encoding='utf-8') as f:
                    dockerfile_content = f.read()
                
                self.analyze_dockerfile_content(service_name, dockerfile_content)
                
            except Exception as e:
                self.log_error(f"Ошибка при чтении Dockerfile для {service_name}: {str(e)}")

    def analyze_dockerfile_content(self, service_name: str, content: str) -> None:
        lines = content.split('\n')
        
        # Проверка базового образа
        from_lines = [line.strip() for line in lines if line.strip().upper().startswith('FROM')]
        
        for from_line in from_lines:
            base_image = from_line.split()[1] if len(from_line.split()) > 1 else ""
            
            # Проверка на небезопасные базовые образы
            for insecure_image in INSECURE_BASE_IMAGES:
                if base_image.startswith(insecure_image.split(':')[0]) and ':latest' in base_image:
                    self.add_vulnerability(
                        service_name,
                        f"Использование небезопасного базового образа с тегом latest: {base_image}",
                        "HIGH"
                    )
                elif base_image == insecure_image:
                    self.add_vulnerability(
                        service_name,
                        f"Использование базового образа без указания версии: {base_image}",
                        "MEDIUM"
                    )
        
        # Проверка на ROOT пользователя
        user_lines = [line.strip() for line in lines if line.strip().upper().startswith('USER')]
        if not user_lines:
            self.add_vulnerability(
                service_name,
                "Отсутствует инструкция USER - контейнер будет работать от root",
                "HIGH"
            )
        else:
            # Проверяем последнюю USER инструкцию
            last_user = user_lines[-1].split()[1] if len(user_lines[-1].split()) > 1 else ""
            if last_user in ['root', '0']:
                self.add_vulnerability(
                    service_name,
                    "Контейнер настроен для работы от пользователя root",
                    "HIGH"
                )

        # Проверка небезопасных паттернов
        for line_num, line in enumerate(lines, 1):
            line = line.strip()
            
            for pattern, description in INSECURE_DOCKERFILE_PATTERNS:
                if re.search(pattern, line, re.IGNORECASE):
                    self.add_vulnerability(
                        service_name,
                        f"{description} (строка {line_num}): {line[:100]}",
                        "MEDIUM" if "chmod 777" in pattern else "HIGH"
                    )
        
        # Проверка на отсутствие HEALTHCHECK
        # healthcheck_lines = [line for line in lines if line.strip().upper().startswith('HEALTHCHECK')]
        # if not healthcheck_lines and service_name in CRITICAL_SERVICES:
        #     self.add_vulnerability(
        #         service_name,
        #         "Отсутствует HEALTHCHECK инструкция для критического сервиса",
        #         "MEDIUM"
        #     )
        
        # Проверка COPY/ADD с широкими правами
        copy_add_lines = [line.strip() for line in lines 
                         if line.strip().upper().startswith(('COPY', 'ADD'))]
        
        for line in copy_add_lines:
            if '--chown=root:root' in line or '--chown=0:0' in line:
                self.add_vulnerability(
                    service_name,
                    f"Копирование файлов с правами root: {line[:100]}",
                    "MEDIUM"
                )
        
        # Проверка на использование SHELL формы вместо EXEC
        cmd_lines = [line.strip() for line in lines 
                    if line.strip().upper().startswith(('RUN', 'CMD', 'ENTRYPOINT'))]
        
        for line in cmd_lines:
            # Проверяем, используется ли shell форма (без квадратных скобок)
            if not re.search(r'\[.*\]', line) and ('&&' in line or '|' in line):
                if line.upper().startswith('RUN') and len(line.split('&&')) > 3:
                    self.add_vulnerability(
                        service_name,
                        f"Сложная RUN инструкция может усложнить отладку: {line[:100]}",
                        "LOW"
                    )

        # Проверка на кэширование пакетных менеджеров
        package_manager_patterns = [
            (r'RUN.*apt-get.*install', r'apt-get.*clean', "apt-get clean"),
            (r'RUN.*yum.*install', r'yum.*clean', "yum clean"),
            (r'RUN.*apk.*add', r'--no-cache', "apk --no-cache")
        ]
        
        content_lower = content.lower()
        for install_pattern, clean_pattern, clean_cmd in package_manager_patterns:
            if re.search(install_pattern, content_lower):
                if not re.search(clean_pattern, content_lower):
                    self.add_vulnerability(
                        service_name,
                        f"Отсутствует очистка кэша пакетного менеджера ({clean_cmd})",
                        "LOW"
                    )

     # Проверяет правильность сетевой топологии системы
    def scan_network_topology(self) -> None:
        self.log_info("Сканирование сетевой топологии...")
        
        # Критические сервисы должны быть подключены к critical_internal
        for service in CRITICAL_SERVICES:
            if service not in self.get_services_in_network("critical_internal"):
                self.add_vulnerability(
                    service, 
                    f"Критический сервис не подключен к сети critical_internal",
                    "HIGH"
                )

            # Проверка, что критические сервисы не подключены напрямую к информационному домену
            for network in ["info_internal"]:
                if service in self.get_services_in_network(network):
                    self.add_vulnerability(
                        service,
                        f"Критический сервис подключен к сети {network}, что нарушает сегрегацию доменов",
                        "HIGH"
                    )

        # Проверка подключения шлюза безопасности (должен быть связан хотя бы с одной сетью)
        if "secure_gateway" not in self.get_services_in_network("critical_internal") and \
        "secure_gateway" not in self.get_services_in_network("info_internal"):
            self.add_vulnerability(
                "secure_gateway",
                "Шлюз безопасности не подключен ни к одной из внутренних сетей",
                "HIGH"
            )

        # Проверка подключения системы связи экипажа
        if "crew_communication" not in self.get_services_in_network("info_internal"):
            self.add_vulnerability(
                "crew_communication", 
                "Система коммуникации экипажа не подключена к сети info_internal",
                "HIGH"
            )

        # Проверка, что crew_communication не подключена к критическим сетям
        if "crew_communication" in self.get_services_in_network("critical_internal"):
            self.add_vulnerability(
                "crew_communication",
                "Система связи экипажа неправильно подключена к сети critical_internal, что нарушает изоляцию",
                "HIGH"
            )

    # Возвращает список сервисов, подключенных к указанной сети
    def get_services_in_network(self, network_name: str) -> List[str]:
        return self.network_map.get(network_name, [])
    
    # Сканирует контейнеры на предмет уязвимостей контейнеризации
    def scan_container_vulnerabilities(self) -> None:
        self.log_info("Сканирование контейнеров на уязвимости...")

        try:
            containers = self.docker_client.containers.list()

            for container in containers:
                # Надёжное определение имени сервиса через label
                service_name = container.labels.get("com.docker.compose.service", "")

                if service_name not in ALL_SERVICES:
                    continue

                # Получаем информацию о контейнере
                container_info = container.attrs

                # Проверка базовых рисков контейнера
                security_checks = [
                    ('Privileged', container_info.get('HostConfig', {}).get('Privileged', False), 
                    "Контейнер запущен в привилегированном режиме, что существенно снижает изоляцию"),

                    ('PID Mode Host', container_info.get('HostConfig', {}).get('PidMode', '') == 'host',
                    "Контейнер использует PID namespace хоста, что снижает изоляцию"),

                    ('Network Mode Host', container_info.get('HostConfig', {}).get('NetworkMode', '') == 'host',
                    "Контейнер использует сетевой namespace хоста, что нарушает сетевую изоляцию"),

                    ('IPC Mode Host', container_info.get('HostConfig', {}).get('IpcMode', '') == 'host',
                    "Контейнер использует IPC namespace хоста, что снижает изоляцию"),

                    ('User Root', not container_info.get('Config', {}).get('User', ''),
                    "Контейнер запущен от имени root пользователя внутри контейнера")
                ]

                for check_name, check_result, description in security_checks:
                    if check_result:
                        self.add_vulnerability(
                            service_name,
                            f"{check_name}: {description}",
                            "HIGH"
                        )

                # Проверка монтирования чувствительных директорий
                mounts = container_info.get('Mounts', [])
                sensitive_paths = ['/var/run/docker.sock', '/proc', '/sys', '/dev', '/etc']

                for mount in mounts:
                    source = mount.get('Source', '')
                    for path in sensitive_paths:
                        if source.startswith(path):
                            self.add_vulnerability(
                                service_name,
                                f"Монтирование чувствительной директории хоста: {source}",
                                "HIGH"
                            )

                # Проверка образа на использование latest
                image = container_info.get('Config', {}).get('Image', '')
                if ':latest' in image:
                    self.add_vulnerability(
                        service_name,
                        "Используется образ с тегом :latest, что может привести к непредсказуемым обновлениям",
                        "MEDIUM"
                    )

        except Exception as e:
            self.log_error(f"Ошибка при сканировании контейнеров: {str(e)}")
        
    # Сканирует открытые порты всех контейнеров
    def scan_open_ports(self) -> None:
        self.log_info("Сканирование открытых портов...")

        try:
            containers = self.docker_client.containers.list()

            for container in containers:
                labels = container.labels
                service_name = labels.get('com.docker.compose.service', container.name)

                # Получаем ожидаемые порты из docker-compose expose
                expected_ports = set()
                if service_name in self.service_configs:
                    ports = self.service_configs[service_name].get('expose', [])
                    for port in ports:
                        if isinstance(port, str):
                            # Пример: "8080/udp"
                            parts = port.split('/')
                            port_num = int(parts[0])
                            proto = parts[1].lower() if len(parts) > 1 else 'tcp'
                            expected_ports.add((port_num, proto))
                        else:
                            expected_ports.add((int(port), 'tcp'))

                # Получаем IP контейнера
                inspect = container.attrs
                networks = inspect.get('NetworkSettings', {}).get('Networks', {})

                for network_name, net_conf in networks.items():
                    ip_address = net_conf.get('IPAddress', '')
                    if not ip_address:
                        continue

                    self.log_info(f"Сканирование {service_name} по адресу {ip_address}...")

                    open_ports = self.scan_ports_with_nmap(ip_address)

                    # Проверка неожиданных портов
                    for port, proto in open_ports:
                        if (port, proto) not in expected_ports:
                            self.add_vulnerability(
                                service_name,
                                f"Обнаружен неожиданный открытый порт {port}/{proto} на {ip_address}",
                                "HIGH"
                            )

                    # Проверка отсутствующих ожидаемых портов
                    for expected in expected_ports:
                        if expected not in open_ports:
                            self.add_vulnerability(
                                service_name,
                                f"Ожидаемый порт {expected[0]}/{expected[1]} не открыт на {ip_address}",
                                "MEDIUM"
                            )

        except Exception as e:
            self.log_error(f"Ошибка при сканировании портов: {str(e)}")

    # Выполняет nmap-сканирование TCP и UDP портов
    def scan_ports_with_nmap(self, ip: str, port_range: str = "1-1000") -> Set[Tuple[int, str]]:
        open_ports = set()

        try:
            scanner = nmap.PortScanner()
            self.log_info(f"Nmap сканирует {ip} в диапазоне портов {port_range}...")
            
            # Сканируем TCP (-sT) и UDP (-sU)
            scanner.scan(hosts=ip, arguments=f"-sT -sU -p {port_range} -T4")

            if ip in scanner.all_hosts():
                for proto in scanner[ip].all_protocols():
                    ports = scanner[ip][proto].keys()
                    for port in ports:
                        state = scanner[ip][proto][port]['state']
                        if state == 'open':
                            open_ports.add((port, proto.lower()))
        except Exception as e:
            self.log_error(f"Nmap ошибка при сканировании {ip}: {str(e)}")

        return open_ports

    # Проверяет наличие и настройку защищенных коммуникаций
    def check_secure_communications(self) -> None:
        self.log_info("Проверка защищенности коммуникаций...")
        
        # Проверка UDP секретных ключей в переменных окружения
        secret_key_services = ["sensors", "controllers", "actuators", "pilot_interface", "avionics"]
        same_key = None
        
        for service in secret_key_services:
            config = self.service_configs.get(service, {})
            env_vars = config.get('environment', [])
            
            for env in env_vars:
                if isinstance(env, str) and env.startswith('UDP_SECRET_KEY='):
                    key = env.split('=')[1]
                    
                    if key == "${UDP_SECRET_KEY}":
                        # Ключ брется из переменной окружения, это хорошо
                        if same_key is None:
                            same_key = key
                    else:
                        # Проверка хардкодинга ключей
                        self.add_vulnerability(
                            service, 
                            "UDP_SECRET_KEY жестко закодирован в docker-compose.yml вместо использования переменной окружения",
                            "HIGH"
                        )
        
        # Проверка наличия сертификатов для HTTPS сервисов
        https_services = ["controllers", "pilot_interface", "avionics", "secure_gateway", "crew_communication"]
        for service in https_services:
            config = self.service_configs.get(service, {})
            volumes = config.get('volumes', [])
            
            # Проверка монтирования сертификатов только для чтения
            for volume in volumes:
                if '/certs:' in volume and not volume.endswith(':ro'):
                    self.add_vulnerability(
                        service, 
                        "Каталог сертификатов не монтируется в режиме только для чтения (ro)",
                        "HIGH"
                    )
    
    # Проверяет правильное разделение сетей и работу межсетевых экранов
    def check_network_segregation(self) -> None:
        self.log_info("Проверка сегрегации сетей...")
        
        # Проверка настройки межсетевых экранов
        firewalls = ["firewall"]
        for fw in firewalls:
            config = self.service_configs.get(fw, {})
            
            # Проверка правильных capabilities
            cap_add = config.get('cap_add', [])
            if 'NET_ADMIN' not in cap_add:
                self.add_vulnerability(
                    fw, 
                    "Отсутствует необходимая возможность NET_ADMIN для работы межсетевого экрана",
                    "HIGH"
                )
            
            # Проверка монтирования конфигурации правил
            volumes = config.get('volumes', [])
            has_rules_config = any('rules.conf' in vol for vol in volumes)
            
            if not has_rules_config:
                self.add_vulnerability(
                    fw, 
                    "Отсутствует конфигурация правил межсетевого экрана",
                    "HIGH"
                )
            
            # Проверка монтирования только для чтения
            for volume in volumes:
                if 'rules.conf' in volume and not volume.endswith(':ro'):
                    self.add_vulnerability(
                        fw, 
                        "Конфигурация правил межсетевого экрана не монтируется в режиме только для чтения (ro)",
                        "MEDIUM"
                    )
        
        # Проверка правильной сегрегации сетей
        networks = self.compose_config.get('networks', {})
        for network_name, network_config in networks.items():
            # Проверка наличия определения подсети
            ipam = network_config.get('ipam', {})
            config = ipam.get('config', [])
            
            if not config or 'subnet' not in config[0]:
                self.add_vulnerability(
                    f"Network {network_name}",
                    "Не определена подсеть (subnet) для сети, что может привести к конфликтам IP адресов",
                    "MEDIUM"
                )

    # проверка секретов и переменных окружения
    def check_secrets_and_env(self) -> None:
        self.log_info("Проверка секретов и переменных окружения...")
        
        # Паттерны для поиска потенциальных секретов
        secret_patterns = [
            (r'password\s*=\s*["\'][^"\']{8,}["\']', "Потенциальный пароль в открытом виде"),
            (r'api[_-]?key\s*=\s*["\'][^"\']{20,}["\']', "Потенциальный API ключ в открытом виде"),
            (r'secret[_-]?key\s*=\s*["\'][^"\']{16,}["\']', "Потенциальный секретный ключ в открытом виде"),
            (r'token\s*=\s*["\'][^"\']{20,}["\']', "Потенциальный токен в открытом виде"),
            (r'private[_-]?key\s*=\s*["\']-----BEGIN', "Приватный ключ в открытом виде"),
        ]
        
        for service_name, service_config in self.service_configs.items():
            env_vars = service_config.get('environment', [])
            
            # Проверка переменных окружения
            for env in env_vars:
                if isinstance(env, str):
                    env_lower = env.lower()
                    
                    # Поиск потенциальных секретов
                    for pattern, description in secret_patterns:
                        if re.search(pattern, env_lower):
                            self.add_vulnerability(
                                service_name,
                                f"{description}: {env.split('=')[0]}",
                                "HIGH"
                            )
                    
                    # Проверка на отладочные переменные в продакшене
                    debug_vars = ['debug=true', 'debug=1', 'dev_mode=true', 'development=true']
                    if any(debug_var in env_lower for debug_var in debug_vars):
                        self.add_vulnerability(
                            service_name,
                            f"Обнаружена отладочная переменная окружения: {env.split('=')[0]}",
                            "MEDIUM"
                        )
            
            # Проверка использования .env файлов
            env_file = service_config.get('env_file')
            if env_file:
                env_file_path = os.path.join(os.path.dirname(self.compose_file), env_file)
                if os.path.exists(env_file_path):
                    try:
                        with open(env_file_path, 'r') as f:
                            env_content = f.read()
                        
                        # Проверка прав доступа к .env файлу
                        file_stat = os.stat(env_file_path)
                        file_mode = oct(file_stat.st_mode)[-3:]
                        
                        if file_mode != '600':
                            self.add_vulnerability(
                                service_name,
                                f"Небезопасные права доступа к .env файлу ({file_mode}), должно быть 600",
                                "HIGH"
                            )
                        
                        # Проверка содержимого .env файла
                        for pattern, description in secret_patterns:
                            if re.search(pattern, env_content, re.IGNORECASE):
                                self.add_vulnerability(
                                    service_name,
                                    f"{description} в .env файле",
                                    "HIGH"
                                )
                    except Exception as e:
                        self.log_error(f"Ошибка при чтении .env файла для {service_name}: {str(e)}")


    # Выводит итоговую сводку по найденным уязвимостям
    def print_summary(self) -> None:
        high_vulns = sum(1 for v in self.vulnerabilities if v['severity'] == 'HIGH')
        medium_vulns = sum(1 for v in self.vulnerabilities if v['severity'] == 'MEDIUM')
        low_vulns = sum(1 for v in self.vulnerabilities if v['severity'] == 'LOW')
        
        print("\n" + "="*80)
        print(f"{Colors.BOLD}ИТОГИ СКАНИРОВАНИЯ УЯЗВИМОСТЕЙ:{Colors.ENDC}")
        print(f"{Colors.FAIL}Критические уязвимости (HIGH): {high_vulns}{Colors.ENDC}")
        print(f"{Colors.WARNING}Средние уязвимости (MEDIUM):  {medium_vulns}{Colors.ENDC}")
        print(f"{Colors.BLUE}Низкие уязвимости (LOW):     {low_vulns}{Colors.ENDC}")
        print("="*80)
        
        if high_vulns > 0:
            print(f"\n{Colors.FAIL}ВНИМАНИЕ: Обнаружены критические уязвимости, требующие немедленного устранения!{Colors.ENDC}")
        
        print("\nПодробный отчет можно сохранить, перенаправив вывод программы в файл:")
        print("python net_scanner.py -f docker-compose.yml > vulnerability_report.txt")
    

    # логирование
    def log_info(self, message: str) -> None:
        """Выводит информационное сообщение"""
        if self.verbose:
            print(f"{Colors.CYAN}[INFO]{Colors.ENDC} {message}")
    
    def log_error(self, message: str) -> None:
        """Выводит сообщение об ошибке"""
        if self.verbose:
            print(f"{Colors.CYAN}[ERROR]{Colors.ENDC} {message}")

            #print(f"{Colors.FAIL}[ERROR]{Colors.ENDC} {message}")
        
    def log_header(self, message: str) -> None:
        """Выводит заголовок раздела"""
        print(f"\n{Colors.HEADER}{Colors.BOLD}{'='*80}{Colors.ENDC}")
        print(f"{Colors.HEADER}{Colors.BOLD}{message}{Colors.ENDC}")
        print(f"{Colors.HEADER}{Colors.BOLD}{'='*80}{Colors.ENDC}\n")

    


# парсинг аргументов командной строки
def parse_arguments():
    # description будет отображаться при --help
    parser = argparse.ArgumentParser(description='Сканер уязвимостей для бортовой сети самолета')
    parser.add_argument('-f', '--file', dest='compose_file', required=True, help='Путь к docker-compose файлу')
    parser.add_argument('-v', '--verbose', action='store_true', help='Выводить подробную информацию о процессе сканирования')
    parser.add_argument('-o', '--output', dest='output_file', help='Файл для сохранения результатов сканирования')
    return parser.parse_args()

# основная функция
def main():
    args = parse_arguments()

    # Перенаправление вывода в файл, если указан
    if args.output_file:
        sys.stdout = open(args.output_file, 'w', encoding='utf-8')
    
    try:
        # проверка наличия файла docker-compose
        if not os.path.isfile(args.compose_file):
            print(f"{Colors.FAIL}[ERROR]{Colors.ENDC} Файл {args.compose_file} не найден")
            sys.exit(1)
        
        # проверка доступа к Docker API
        try:
            docker_client = docker.from_env()
            docker_client.ping()
        except Exception as e:
            print(f"{Colors.FAIL}[ERROR]{Colors.ENDC} Не удалось подключиться к Docker: {str(e)}")
            print("Убедитесь, что Docker запущен и у вас есть права на выполнение команд Docker.")
            sys.exit(1)
        
        # Запуск сканера
        scanner = Vulnerability_scanner(args.compose_file, args.verbose)
        scanner.scan_all()
        
    except KeyboardInterrupt:
        print(f"\n{Colors.WARNING}Сканирование прервано пользователем{Colors.ENDC}")
        sys.exit(130)
    except Exception as e:
        print(f"{Colors.FAIL}[ERROR]{Colors.ENDC} Необработанное исключение: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
    finally:
        # возвращаем стандартный вывод, если был указан файл
        if args.output_file and sys.stdout != sys.__stdout__:
            sys.stdout.close()
            sys.stdout = sys.__stdout__


if __name__ == "__main__":
    main()