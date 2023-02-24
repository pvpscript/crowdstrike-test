import os
import sys
import time
import csv
import falconpy
import json

import pandas as pd

from datetime import datetime

pretty = lambda d: print(json.dumps(d, indent=4))

class CommandException(Exception):
    """ Raised when a command is unable to be ran """
    pass

class QueryExecutionException(Exception):
    """ Raised when there's an error running a falcon data query """
    pass

class MissingDataException(Exception):
    """ Raised when there's no data for a given serial number """
    pass

class DetailsFetchException(Exception):
    """ Raised when it wasn't possible to fetch details for a given serial number """
    pass

class SessionException(Exception):
    """ """
    pass

class Report:
    def __init__(self):
        self._report_data = {}

    def __setitem__(self, key, value):
        if self._report_data.get(key) is None:
            self._report_data[key] = [value]
        else:
            self._report_data[key].append(value)

    def _csv_output_file(self):
        name = f"report_{datetime.now()}.csv"
        file_obj = open(name, 'w')

        return csv.writer(file_obj)

    def _validate_dict(self):
        keys = list(self._report_data)
        size = len(self._report_data) - 1

        return all(
            [
                len(self._report_data[keys[i]]) == len(self._report_data[keys[i+1]])
                for i in range(size)
            ]
        )

    def _dict_info(self):
        keys = self._report_data.keys()
        first_key = list(keys)[0]

        return keys, range(len(self._report_data[first_key]))

    def debug(self):
        return self._report_data

    def export_csv(self):
        assert(self._validate_dict()), "Inconsistent column length"
        
        csv_writer = self._csv_output_file()

        keys, rg_rows = self._dict_info()
        data = [[self._report_data[k][row] for k in keys] for row in rg_rows]

        csv_writer.writerow(keys)
        csv_writer.writerows(data)

    #def export_csv(self):
    #    name = f"report_{datetime.now()}.csv"
    #    df = pd.DataFrame(self._report_data)
    #    df.to_csv(name)

class CommandsMeta(type):
    MAC = lambda self, new_name: ("runscript -Raw=``` "
                                  f"sudo scutil --set ComputerName '{new_name}' && "
                                  f"sudo scutil --set LocalHostName '{new_name}' && "
                                  f"sudo scutil --set HostName '{new_name}'```")
    WINDOWS = lambda self, new_name: ("runscript -Raw=``` "
                                      f"Rename-Computer -NewName {new_name} -Force ```")
    LINUX = lambda self, new_name: f"runscript -Raw=``` hostname {new_name} ```"

    def __getitem__(self, name):
        lower_name = name.lower()
        match lower_name:
            case 'mac':
                return self.MAC
            case 'windows':
                return self.WINDOWS
            case 'linux':
                return self.LINUX
            case _:
                raise Exception(f"Unknown platorm '{name}'")

class Commands(metaclass=CommandsMeta):
    def __getattr__(self, name):
        return getattr(type(self), name)


class FalconAccess:
    ID_KEY="FALCON_CLIENT_ID"
    SECRET_KEY="FALCON_CLIENT_SECRET"

    def __init__(self):
        self._hosts = None
        self._rtr = None
        self._rtra = None

    @property
    def hosts(self):
        if self._hosts is None:
            self._hosts = falconpy.Hosts(client_id=os.getenv(self.ID_KEY),
                                         client_secret=os.getenv(self.SECRET_KEY))

        return self._hosts

    @property
    def real_time_response(self):
        if self._rtr is None:
            self._rtr = falconpy.RealTimeResponse(client_id=os.getenv(self.ID_KEY),
                                                  client_secret=os.getenv(self.SECRET_KEY))

        return self._rtr

    @property
    def real_time_response_admin(self):
        if self._rtra is None:
            self._rtra = falconpy.RealTimeResponseAdmin(client_id=os.getenv(self.ID_KEY),
                                                       client_secret=os.getenv(self.SECRET_KEY))

        return self._rtra

class FalconData:
    def __init__(self, falcon_access):
        self._hosts = falcon_access.hosts
        print("Initiated falcon data")

    def _filter_by_serial_number(self, serial_number):
        return f"serial_number:'{serial_number}'"

    def _resources(self, data):
        return data['body']['resources']

    def devices(self, serial_number):
        device_res = self._hosts.query_devices_by_filter(
            filter=self._filter_by_serial_number(serial_number)
        )

        if device_res['status_code'] != 200:
            raise QueryExecutionException(f"Query execution error for serial number: {serial_number}")
        if len(resources := self._resources(device_res)) == 0:
            raise MissingDataException(f"No data found for serial number: {serial_number}")

        return resources

    def details(self, device_ids):
        details_res = self._hosts.get_device_details(ids=device_ids)

        if details_res['status_code'] != 200:
            raise DetailsFetchException(f"Unable to get device details for {device_ids}")
        
        return self._resources(details_res)

class FalconDevice:
    def __init__(self, falcon_access):
        self._rtr = falcon_access.real_time_response
        print("Initiated falcon device")

    def _resources(self, data):
        return data['body']['resources'][0]

    def init_sessions(self, device_ids, timeout=180):
        sessions = []
        for device_id in device_ids:
            sess = self._rtr.init_session(device_id=device_id,
                                          queue_offline=False,
                                          timeout=timeout)

            if (status := sess['status_code']) != 201:
                raise SessionException(f"Unable to start session for device {device_id}, received status: {status}")
            else:
                sessions.append(self._resources(sess))

        return sessions

class FalconAdmin:
    def __init__(self, falcon_access):
        self._rtra = falcon_access.real_time_response_admin
        print("Initiated falcon admin")

    def _resources(self, data):
        return data['body']['resources'][0]

    def _check_command_not_completed(self, cloud_request_id):
        cmd_check = self._rtra.RTR_CheckAdminCommandStatus(
            cloud_request_id=cloud_request_id
        )

        return self._resources(cmd_check)['complete'] == False

    def run_command(self, session_id, command, await_complete=True, tries=5):
        cmd = self._rtra.RTR_ExecuteAdminCommand(command_string=command,
                                                 persist_all=True,
                                                 session_id=session_id)
        
        if cmd['status_code'] != 201:
            raise CommandException(f"Unable to run command {command} on session {session_id}")

        resources = self._resources(cmd)

        if await_complete:
            cloud_request_id = resources['cloud_request_id']
            curr_try = 0
            while (self._check_command_not_completed(cloud_request_id) and
                   curr_try < tries):
                time.sleep(1)
                curr_try += 1

        return resources if curr_try < tries else None
    
    def get_command_status(self, cloud_request_id):
        cmd_status = self._rtra.RTR_CheckAdminCommandStatus(
            cloud_request_id=cloud_request_id
        )

        return self._resources(cmd_status)

def read_csv(file_name):
    in_file = open(file_name)
    return csv.DictReader(in_file)

def main():
    report = Report()

    platform = lambda d: d['platform_name']
    hostname = lambda d: d['hostname']
    last_seen = lambda d: d['last_seen']
    sessid = lambda s: s['session_id']

    access = FalconAccess()

    falcon_data = FalconData(access)
    falcon_device = FalconDevice(access)
    falcon_admin = FalconAdmin(access)

    csv_data = read_csv('devices-to-rename.csv')

    for data in csv_data:
        try:
            devices = falcon_data.devices(data['serial_number'])
            print("fetched devices")
            details = falcon_data.details(devices)
            print("fetched details")
            for detail in details:
                report['new_name'] = data['new_name']
                report['owner'] = data['owner']
                report['serial_number'] = data['serial_number']
                report['name'] = hostname(detail)
                report['platform'] = platform(detail)
                report['last_seen'] = last_seen(detail)

                try:
                    sessions = falcon_device.init_sessions([detail['device_id']])
                    print("opened sessions")

                    for session in sessions:
                        command = Commands[platform(detail)](data['new_name'])
                        resources = falcon_admin.run_command(sessid(session), command)
                        command_status = falcon_admin.get_command_status(resources['cloud_request_id'])

                        report['stdout'] = command_status['stdout']
                        report['stderr'] = command_status['stderr']
                except Exception as e:
                    report['stdout'] = ""
                    report['stderr'] = ""
                    report['status'] = e
                else:
                    report['status'] = "Success!"
        except Exception as e:
            print(f"An error occurred: {e}")
            report['status'] = e

    report.export_csv()