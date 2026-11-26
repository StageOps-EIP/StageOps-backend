"""Exercise the live API against a disposable integration stack."""

import json
import os
import unittest
import urllib.error
import urllib.request
import uuid


class BusinessFlow(unittest.TestCase):
    def request(self, method, path, expected, *, token=None, payload=None):
        headers = {}
        body = None
        if payload is not None:
            headers["Content-Type"] = "application/json"
            body = json.dumps(payload).encode()
        if token is not None:
            headers["Authorization"] = f"Bearer {token}"
        request = urllib.request.Request(
            os.environ["STAGEOPS_E2E_URL"].rstrip("/") + "/api" + path,
            data=body,
            headers=headers,
            method=method,
        )
        try:
            response = urllib.request.urlopen(request, timeout=10)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            self.assertEqual(response.status, expected, f"{method} {path}")
            data = response.read()
            return json.loads(data) if data else None

    def test_project_equipment_incident_lifecycle(self):
        admin_session = self.request("POST", "/auth/login", 200, payload={
            "email": os.environ["STAGEOPS_E2E_ADMIN_EMAIL"],
            "password": os.environ["STAGEOPS_E2E_ADMIN_PASSWORD"],
        })
        admin = admin_session["token"]
        self.assertTrue(admin)
        self.assertTrue(admin == admin_session["access_token"], "Legacy token differs")
        self.assertTrue(admin_session["refresh_token"])

        technician_session = self.request("POST", "/auth/register", 201, payload={
            "email": f"technician-{uuid.uuid4().hex}@example.com",
            "password": f"Test-Technician-42!{uuid.uuid4().hex}",
        })
        technician = technician_session["access_token"]
        self.assertTrue(technician == technician_session["token"], "Legacy token differs")
        technician_id = self.request("GET", "/auth/me", 200, token=technician)["id"]
        project = self.request("POST", "/projects/", 201, token=admin, payload={
            "name": f"Spectacle {uuid.uuid4().hex}",
            "venue": "Grande salle",
            "start_date": "2026-11-24",
            "end_date": "2026-11-27",
            "modules_config": {"lighting": True, "audio": False, "stage": False},
        })
        project_path = f"/projects/{project['id']}"
        equipment_path = project_path + "/equipment/lighting"
        incident_path = project_path + "/incidents/lighting"
        inactive = self.request(
            "POST", project_path + "/equipment/audio", 403, token=admin,
            payload={"name": "Micro", "kind": "microphone"},
        )
        self.assertEqual(inactive["error"]["code"], "MODULE_INACTIVE")
        self.assertEqual(
            self.request("GET", equipment_path, 403, token=technician)["error"]["code"],
            "FORBIDDEN",
        )
        self.request("PATCH", f"/users/{technician_id}/modules", 200, token=admin,
                     payload={"assigned_modules": ["lumiere"]})

        fixture = {
            "name": "Lyre jardin",
            "kind": "moving-head",
            "available_from": "2026-11-25",
            "available_to": "2026-11-26",
            "dmx_universe": 1,
            "dmx_address": 100,
            "dmx_channels": 16,
        }
        equipment = self.request("POST", equipment_path, 201, token=technician,
                                 payload=fixture)
        equipment_id = equipment["id"]
        self.assertEqual(equipment["status"], "ok")
        conflict = self.request(
            "POST", equipment_path, 409, token=technician,
            payload={**fixture, "name": "Lyre cour", "dmx_address": 110},
        )
        self.assertEqual(conflict["error"]["code"], "DMX_CONFLICT")
        for date, expected_ids in [("2026-11-24", []), ("2026-11-25", [equipment_id])]:
            items = self.request("GET", f"{equipment_path}?date={date}", 200, token=admin)
            self.assertEqual([item["id"] for item in items], expected_ids)

        report = {
            "title": "Projecteur sans réponse",
            "description": "Le projecteur ne répond plus au DMX.",
            "severity": "high",
            "equipment_id": equipment_id,
        }
        self.request("POST", incident_path, 400, token=technician, payload=report)
        incident = self.request("POST", incident_path, 201, token=technician,
                                payload={**report, "date": "2026-11-25"})
        incident_id = incident["id"]
        self.assertEqual(incident["equipment_id"], equipment_id)
        equipment_detail = f"{equipment_path}/{equipment_id}"
        self.assertEqual(
            self.request("GET", equipment_detail, 200, token=admin)["status"], "to-check"
        )
        for date, expected_ids in [("2026-11-25", [incident_id]), ("2026-11-26", [])]:
            items = self.request("GET", f"{incident_path}?date={date}", 200, token=admin)
            self.assertEqual([item["id"] for item in items], expected_ids)

        incident_detail = f"{incident_path}/{incident_id}"
        resolved = self.request("PATCH", incident_detail, 200, token=technician,
                                payload={**report, "status": "resolved"})
        self.assertEqual(resolved["status"], "resolved")
        self.assertEqual(resolved["date"], "2026-11-25")
        self.assertTrue(resolved["resolved_at"])
        self.assertEqual(
            self.request("GET", equipment_detail, 200, token=admin)["status"], "ok"
        )

        renewed = self.request("POST", "/auth/refresh", 200, payload={
            "refresh_token": technician_session["refresh_token"],
        })
        self.assertTrue(
            renewed["refresh_token"] != technician_session["refresh_token"],
            "Refresh token was not rotated",
        )
        self.assertEqual(
            self.request("GET", "/auth/me", 200, token=renewed["access_token"])["id"],
            technician_id,
        )
        self.request("POST", "/auth/logout", 204,
                     payload={"refresh_token": renewed["refresh_token"]})
        self.request("GET", "/auth/me", 401, token=renewed["access_token"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
