from mythic_container.MythicCommandBase import *
import json


class PsArguments(TaskArguments):

    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="full",
                cli_name="full",
                display_name="Fetch full command line",
                type=ParameterType.Boolean,
                description=(
                    "On Windows, also pull each process's full CommandLine via "
                    "NtQueryInformationProcess + ReadProcessMemory of its PEB. "
                    "Processes we can't open with PROCESS_VM_READ (higher "
                    "privilege, protected) will come back with an empty "
                    "command_line. No-op on Linux (already read from /proc)."
                ),
                default_value=False,
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=False, group_name="Default", ui_position=1
                    ),
                ],
            ),
        ]

    async def parse_arguments(self):
        s = self.command_line.strip()
        if s == "":
            self.add_arg("full", False)
            return
        if s.startswith("{"):
            try:
                self.load_args_from_dictionary(json.loads(self.command_line))
                return
            except Exception:
                pass
        if s.lower() in ("-full", "--full", "full", "-f"):
            self.add_arg("full", True)
            return
        raise Exception("ps takes an optional '-full' flag.")


class PsCommand(CommandBase):
    cmd = "ps"
    needs_admin = False
    help_cmd = "ps [-full]"
    description = (
        "Get a process listing. With -full, also fetch each process's "
        "command line (slower, Windows reads the PEB; needs read access)."
    )
    version = 4
    supported_ui_features = ["process_browser:list"]
    author = "@djhohnstein"
    argument_class = PsArguments
    attackmapping = ["T1106"]
    browser_script = BrowserScript(script_name="ps_new", author="@djhohnstein")
    attributes = CommandAttributes(
        suggested_command=True
    )

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )
        if taskData.args.get_arg("full"):
            response.DisplayParams = "-full"
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp
