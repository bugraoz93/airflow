#
# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.
from __future__ import annotations

import argparse
import contextlib
import json
import os
from datetime import datetime, timedelta
from io import StringIO
from unittest import mock

import pendulum
import pytest
import time_machine

from airflow import settings
from airflow.cli import cli_parser
from airflow.cli.commands.remote_commands import dag_command
from airflow.exceptions import AirflowException
from airflow.models import DagBag, DagModel, DagRun
from airflow.utils import timezone
from airflow.utils.session import create_session
from airflow.utils.types import DagRunType

from tests.models import TEST_DAGS_FOLDER
from tests_common.test_utils.config import conf_vars
from tests_common.test_utils.db import (
    clear_db_dags,
    clear_db_import_errors,
    clear_db_runs,
    parse_and_sync_to_db,
)

DEFAULT_DATE = timezone.make_aware(datetime(2015, 1, 1), timezone=timezone.utc)
if pendulum.__version__.startswith("3"):
    DEFAULT_DATE_REPR = DEFAULT_DATE.isoformat(sep=" ")
else:
    DEFAULT_DATE_REPR = DEFAULT_DATE.isoformat()

# TODO: Check if tests needs side effects - locally there's missing DAG

pytestmark = pytest.mark.db_test


class TestCliDags:
    parser: argparse.ArgumentParser

    @classmethod
    def setup_class(cls):
        parse_and_sync_to_db(os.devnull, include_examples=True)
        cls.parser = cli_parser.get_parser()

    @classmethod
    def teardown_class(cls) -> None:
        clear_db_runs()
        clear_db_dags()

    def setup_method(self):
        clear_db_runs()
        clear_db_import_errors()

    def teardown_method(self):
        clear_db_import_errors()

    def test_next_execution(self, tmp_path):
        dag_test_list = [
            ("future_schedule_daily", "timedelta(days=5)", "'0 0 * * *'", "True"),
            ("future_schedule_every_4_hours", "timedelta(days=5)", "timedelta(hours=4)", "True"),
            ("future_schedule_once", "timedelta(days=5)", "'@once'", "True"),
            ("future_schedule_none", "timedelta(days=5)", "None", "True"),
            ("past_schedule_once", "timedelta(days=-5)", "'@once'", "True"),
            ("past_schedule_daily", "timedelta(days=-5)", "'0 0 * * *'", "True"),
            ("past_schedule_daily_catchup_false", "timedelta(days=-5)", "'0 0 * * *'", "False"),
        ]

        for f in dag_test_list:
            file_content = os.linesep.join(
                [
                    "from airflow import DAG",
                    "from airflow.providers.standard.operators.empty import EmptyOperator",
                    "from datetime import timedelta; from pendulum import today",
                    f"dag = DAG('{f[0]}', start_date=today() + {f[1]}, schedule={f[2]}, catchup={f[3]})",
                    "task = EmptyOperator(task_id='empty_task',dag=dag)",
                ]
            )
            dag_file = tmp_path / f"{f[0]}.py"
            dag_file.write_text(file_content)

        with time_machine.travel(DEFAULT_DATE):
            clear_db_dags()
            parse_and_sync_to_db(tmp_path, include_examples=False)

        default_run = DEFAULT_DATE
        future_run = default_run + timedelta(days=5)
        past_run = default_run + timedelta(days=-5)

        expected_output = {
            "future_schedule_daily": (
                future_run.isoformat(),
                future_run.isoformat() + os.linesep + (future_run + timedelta(days=1)).isoformat(),
            ),
            "future_schedule_every_4_hours": (
                future_run.isoformat(),
                future_run.isoformat() + os.linesep + (future_run + timedelta(hours=4)).isoformat(),
            ),
            "future_schedule_once": (future_run.isoformat(), future_run.isoformat() + os.linesep + "None"),
            "future_schedule_none": ("None", "None"),
            "past_schedule_once": (past_run.isoformat(), "None"),
            "past_schedule_daily": (
                past_run.isoformat(),
                past_run.isoformat() + os.linesep + (past_run + timedelta(days=1)).isoformat(),
            ),
            "past_schedule_daily_catchup_false": (
                (default_run - timedelta(days=1)).isoformat(),
                (default_run - timedelta(days=1)).isoformat() + os.linesep + default_run.isoformat(),
            ),
        }

        for dag_id in expected_output:
            # Test num-executions = 1 (default)
            args = self.parser.parse_args(["dags", "next-execution", dag_id, "-S", str(tmp_path)])
            with contextlib.redirect_stdout(StringIO()) as temp_stdout:
                dag_command.dag_next_execution(args)
                out = temp_stdout.getvalue()
            assert expected_output[dag_id][0] in out

            # Test num-executions = 2
            args = self.parser.parse_args(
                ["dags", "next-execution", dag_id, "--num-executions", "2", "-S", str(tmp_path)]
            )
            with contextlib.redirect_stdout(StringIO()) as temp_stdout:
                dag_command.dag_next_execution(args)
                out = temp_stdout.getvalue()
            assert expected_output[dag_id][1] in out

        # Rebuild Test DB for other tests
        clear_db_dags()
        parse_and_sync_to_db(os.devnull, include_examples=True)

    @conf_vars({("core", "load_examples"): "true"})
    def test_cli_report(self):
        args = self.parser.parse_args(["dags", "report", "--output", "json"])
        with contextlib.redirect_stdout(StringIO()) as temp_stdout:
            dag_command.dag_report(args)
            out = temp_stdout.getvalue()

        assert "airflow/example_dags/example_complex.py" in out
        assert "example_complex" in out

    @conf_vars({("core", "load_examples"): "true"})
    def test_cli_get_dag_details(self):
        args = self.parser.parse_args(["dags", "details", "example_complex", "--output", "yaml"])
        with contextlib.redirect_stdout(StringIO()) as temp_stdout:
            dag_command.dag_details(args)
            out = temp_stdout.getvalue()

        dag_detail_fields = dag_command.DAGSchema().fields.keys()

        # Check if DAG Details field are present
        for field in dag_detail_fields:
            assert field in out

        # Check if identifying values are present
        dag_details_values = ["airflow", "airflow/example_dags/example_complex.py", "16", "example_complex"]

        for value in dag_details_values:
            assert value in out

    @conf_vars({("core", "load_examples"): "true"})
    def test_cli_list_dags(self):
        args = self.parser.parse_args(["dags", "list", "--output", "json"])
        with contextlib.redirect_stdout(StringIO()) as temp_stdout:
            dag_command.dag_list_dags(args)
            out = temp_stdout.getvalue()
            dag_list = json.loads(out)
        for key in ["dag_id", "fileloc", "owners", "is_paused"]:
            assert key in dag_list[0]
        assert any("airflow/example_dags/example_complex.py" in d["fileloc"] for d in dag_list)

    @conf_vars({("core", "load_examples"): "true"})
    def test_cli_list_dags_custom_cols(self):
        args = self.parser.parse_args(
            ["dags", "list", "--output", "json", "--columns", "dag_id,last_parsed_time"]
        )
        with contextlib.redirect_stdout(StringIO()) as temp_stdout:
            dag_command.dag_list_dags(args)
            out = temp_stdout.getvalue()
            dag_list = json.loads(out)
        for key in ["dag_id", "last_parsed_time"]:
            assert key in dag_list[0]
        for key in ["fileloc", "owners", "is_paused"]:
            assert key not in dag_list[0]

    @conf_vars({("core", "load_examples"): "true"})
    def test_cli_list_dags_invalid_cols(self):
        args = self.parser.parse_args(["dags", "list", "--output", "json", "--columns", "dag_id,invalid_col"])
        with contextlib.redirect_stderr(StringIO()) as temp_stderr:
            dag_command.dag_list_dags(args)
            out = temp_stderr.getvalue()
        assert "Ignoring the following invalid columns: ['invalid_col']" in out

    @conf_vars({("core", "load_examples"): "false"})
    def test_cli_list_dags_prints_import_errors(self, configure_testing_dag_bundle, get_test_dag):
        path_to_parse = TEST_DAGS_FOLDER / "test_invalid_cron.py"
        get_test_dag("test_invalid_cron")

        args = self.parser.parse_args(["dags", "list", "--output", "yaml", "--bundle-name", "testing"])

        with configure_testing_dag_bundle(path_to_parse):
            with contextlib.redirect_stderr(StringIO()) as temp_stderr:
                dag_command.dag_list_dags(args)
                out = temp_stderr.getvalue()

        assert "Failed to load all files." in out

    @conf_vars({("core", "load_examples"): "true"})
    @mock.patch("airflow.models.DagModel.get_dagmodel")
    def test_list_dags_none_get_dagmodel(self, mock_get_dagmodel):
        mock_get_dagmodel.return_value = None
        args = self.parser.parse_args(["dags", "list", "--output", "json"])
        with contextlib.redirect_stdout(StringIO()) as temp_stdout:
            dag_command.dag_list_dags(args)
            out = temp_stdout.getvalue()
            dag_list = json.loads(out)
        for key in ["dag_id", "fileloc", "owners", "is_paused"]:
            assert key in dag_list[0]
        assert any("airflow/example_dags/example_complex.py" in d["fileloc"] for d in dag_list)

    @conf_vars({("core", "load_examples"): "true"})
    def test_dagbag_dag_col(self):
        valid_cols = [c for c in dag_command.DAGSchema().fields]
        dagbag = DagBag(include_examples=True)
        dag_details = dag_command._get_dagbag_dag_details(dagbag.get_dag("tutorial_dag"))
        assert list(dag_details.keys()) == valid_cols

    @conf_vars({("core", "load_examples"): "false"})
    def test_cli_list_import_errors(self):
        dag_path = os.path.join(TEST_DAGS_FOLDER, "test_invalid_cron.py")
        args = self.parser.parse_args(
            ["dags", "list-import-errors", "--output", "yaml", "--subdir", dag_path]
        )
        with contextlib.redirect_stdout(StringIO()) as temp_stdout:
            with pytest.raises(SystemExit) as err_ctx:
                dag_command.dag_list_import_errors(args)
            out = temp_stdout.getvalue()
        assert "[0 100 * * *] is not acceptable, out of range" in out
        assert dag_path in out
        assert err_ctx.value.code == 1

    def test_cli_list_dag_runs(self):
        dag_command.dag_trigger(
            self.parser.parse_args(
                [
                    "dags",
                    "trigger",
                    "example_bash_operator",
                ]
            )
        )
        args = self.parser.parse_args(
            [
                "dags",
                "list-runs",
                "example_bash_operator",
                "--no-backfill",
                "--start-date",
                DEFAULT_DATE.isoformat(),
                "--end-date",
                timezone.make_aware(datetime.max).isoformat(),
            ]
        )
        dag_command.dag_list_dag_runs(args)

    def test_cli_list_jobs_with_args(self):
        args = self.parser.parse_args(
            [
                "dags",
                "list-jobs",
                "--dag-id",
                "example_bash_operator",
                "--state",
                "success",
                "--limit",
                "100",
                "--output",
                "json",
            ]
        )
        dag_command.dag_list_jobs(args)

    def test_pause(self):
        args = self.parser.parse_args(["dags", "pause", "example_bash_operator"])
        dag_command.dag_pause(args)
        assert DagModel.get_dagmodel("example_bash_operator").is_paused
        dag_command.dag_unpause(args)
        assert not DagModel.get_dagmodel("example_bash_operator").is_paused

    @mock.patch("airflow.cli.commands.remote_commands.dag_command.ask_yesno")
    def test_pause_regex(self, mock_yesno):
        args = self.parser.parse_args(["dags", "pause", "^example_.*$", "--treat-dag-id-as-regex"])
        dag_command.dag_pause(args)
        mock_yesno.assert_called_once()
        assert DagModel.get_dagmodel("example_bash_decorator").is_paused
        assert DagModel.get_dagmodel("example_kubernetes_executor").is_paused
        assert DagModel.get_dagmodel("example_xcom_args").is_paused

        args = self.parser.parse_args(["dags", "unpause", "^example_.*$", "--treat-dag-id-as-regex"])
        dag_command.dag_unpause(args)
        assert not DagModel.get_dagmodel("example_bash_decorator").is_paused
        assert not DagModel.get_dagmodel("example_kubernetes_executor").is_paused
        assert not DagModel.get_dagmodel("example_xcom_args").is_paused

    @mock.patch("airflow.cli.commands.remote_commands.dag_command.ask_yesno")
    def test_pause_regex_operation_cancelled(self, ask_yesno, capsys):
        args = self.parser.parse_args(["dags", "pause", "example_bash_operator", "--treat-dag-id-as-regex"])
        ask_yesno.return_value = False
        dag_command.dag_pause(args)
        stdout = capsys.readouterr().out
        assert "Operation cancelled by user" in stdout

    @mock.patch("airflow.cli.commands.remote_commands.dag_command.ask_yesno")
    def test_pause_regex_yes(self, mock_yesno):
        args = self.parser.parse_args(["dags", "pause", ".*", "--treat-dag-id-as-regex", "--yes"])
        dag_command.dag_pause(args)
        mock_yesno.assert_not_called()
        dag_command.dag_unpause(args)

    def test_pause_non_existing_dag_do_not_error(self):
        args = self.parser.parse_args(["dags", "pause", "non_existing_dag"])
        with contextlib.redirect_stdout(StringIO()) as temp_stdout:
            dag_command.dag_pause(args)
            out = temp_stdout.getvalue().strip().splitlines()[-1]
        assert out == "No unpaused DAGs were found"

    def test_unpause_non_existing_dag_do_not_error(self):
        args = self.parser.parse_args(["dags", "unpause", "non_existing_dag"])
        with contextlib.redirect_stdout(StringIO()) as temp_stdout:
            dag_command.dag_unpause(args)
            out = temp_stdout.getvalue().strip().splitlines()[-1]
        assert out == "No paused DAGs were found"

    def test_unpause_already_unpaused_dag_do_not_error(self):
        args = self.parser.parse_args(["dags", "unpause", "example_bash_operator", "--yes"])
        with contextlib.redirect_stdout(StringIO()) as temp_stdout:
            dag_command.dag_unpause(args)
            out = temp_stdout.getvalue().strip().splitlines()[-1]
        assert out == "No paused DAGs were found"

    def test_pausing_already_paused_dag_do_not_error(self):
        args = self.parser.parse_args(["dags", "pause", "example_bash_operator", "--yes"])
        with contextlib.redirect_stdout(StringIO()) as temp_stdout:
            dag_command.dag_pause(args)
            dag_command.dag_pause(args)
            out = temp_stdout.getvalue().strip().splitlines()[-1]
        assert out == "No unpaused DAGs were found"

    def test_trigger_dag(self):
        dag_command.dag_trigger(
            self.parser.parse_args(
                [
                    "dags",
                    "trigger",
                    "example_bash_operator",
                    "--run-id=test_trigger_dag",
                    '--conf={"foo": "bar"}',
                ],
            ),
        )
        with create_session() as session:
            dagrun = session.query(DagRun).filter(DagRun.run_id == "test_trigger_dag").one()

        assert dagrun, "DagRun not created"
        assert dagrun.run_type == DagRunType.MANUAL
        assert dagrun.conf == {"foo": "bar"}

        # logical_date is None as it's not provided
        assert dagrun.logical_date is None

        # data_interval is None as logical_date is None
        assert dagrun.data_interval_start is None
        assert dagrun.data_interval_end is None

    def test_trigger_dag_with_microseconds(self):
        dag_command.dag_trigger(
            self.parser.parse_args(
                [
                    "dags",
                    "trigger",
                    "example_bash_operator",
                    "--run-id=test_trigger_dag_with_micro",
                    "--exec-date=2021-06-04T09:00:00.000001+08:00",
                    "--no-replace-microseconds",
                ],
            )
        )

        with create_session() as session:
            dagrun = session.query(DagRun).filter(DagRun.run_id == "test_trigger_dag_with_micro").one()

        assert dagrun, "DagRun not created"
        assert dagrun.run_type == DagRunType.MANUAL
        assert dagrun.logical_date.isoformat(timespec="microseconds") == "2021-06-04T01:00:00.000001+00:00"

    def test_trigger_dag_invalid_conf(self):
        with pytest.raises(ValueError):
            dag_command.dag_trigger(
                self.parser.parse_args(
                    [
                        "dags",
                        "trigger",
                        "example_bash_operator",
                        "--run-id",
                        "trigger_dag_xxx",
                        "--conf",
                        "NOT JSON",
                    ]
                ),
            )

    def test_trigger_dag_output_as_json(self):
        args = self.parser.parse_args(
            [
                "dags",
                "trigger",
                "example_bash_operator",
                "--run-id",
                "trigger_dag_xxx",
                "--conf",
                '{"conf1": "val1", "conf2": "val2"}',
                "--output=json",
            ]
        )
        with contextlib.redirect_stdout(StringIO()) as temp_stdout:
            dag_command.dag_trigger(args)
            # get the last line from the logs ignoring all logging lines
            out = temp_stdout.getvalue().strip().splitlines()[-1]
        parsed_out = json.loads(out)

        assert len(parsed_out) == 1
        assert parsed_out[0]["dag_id"] == "example_bash_operator"
        assert parsed_out[0]["dag_run_id"] == "trigger_dag_xxx"
        assert parsed_out[0]["conf"] == {"conf1": "val1", "conf2": "val2"}

    def test_delete_dag(self):
        DM = DagModel
        key = "my_dag_id"
        session = settings.Session()
        session.add(DM(dag_id=key))
        session.commit()
        dag_command.dag_delete(self.parser.parse_args(["dags", "delete", key, "--yes"]))
        assert session.query(DM).filter_by(dag_id=key).count() == 0
        with pytest.raises(AirflowException):
            dag_command.dag_delete(
                self.parser.parse_args(["dags", "delete", "does_not_exist_dag", "--yes"]),
            )

    def test_delete_dag_existing_file(self, tmp_path):
        # Test to check that the DAG should be deleted even if
        # the file containing it is not deleted
        path = tmp_path / "testfile"
        DM = DagModel
        key = "my_dag_id"
        session = settings.Session()
        session.add(DM(dag_id=key, fileloc=os.fspath(path)))
        session.commit()
        dag_command.dag_delete(self.parser.parse_args(["dags", "delete", key, "--yes"]))
        assert session.query(DM).filter_by(dag_id=key).count() == 0

    def test_cli_list_jobs(self):
        args = self.parser.parse_args(["dags", "list-jobs"])
        dag_command.dag_list_jobs(args)

    def test_dag_state(self):
        assert (
            dag_command.dag_state(
                self.parser.parse_args(["dags", "state", "example_bash_operator", DEFAULT_DATE.isoformat()])
            )
            is None
        )
