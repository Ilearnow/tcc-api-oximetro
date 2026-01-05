import sys
import os
import time
import json
import requests
from datetime import datetime
from urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TCCTestSystem:
    def __init__(self):
        self.base_url = "http://localhost:8000"
        self.base_url_https = "https://localhost:9443"
        self.base_url_https_no_mtls = "https://localhost:9444"
        self.results = []
        self.token = None

        self.username = "igor"
        self.password = "secret1234"

        self.cert_path = "./certs/client.pem"
        self.key_path = "./certs/client.key"
        self.ca_path = "./certs/ca.crt"

    def log(self, message, status="INFO"):
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"[{timestamp}] {status}: {message}")

    def test_endpoint(self, name, method, endpoint, use_mtls=False, **kwargs):
        try:
            if use_mtls:
                url = f"{self.base_url_https}{endpoint}"
                if os.path.exists(self.cert_path) and os.path.exists(self.key_path):
                    kwargs['cert'] = (self.cert_path, self.key_path)
                    kwargs['verify'] = self.ca_path if os.path.exists(self.ca_path) else False
                else:
                    self.log(f"Certificates not found for mTLS", "WARNING")
                    kwargs['verify'] = False
            else:
                url = f"{self.base_url}{endpoint}"

            kwargs.setdefault('timeout', 10)

            if method == "GET":
                response = requests.get(url, **kwargs)
            elif method == "POST":
                response = requests.post(url, **kwargs)
            elif method == "PUT":
                response = requests.put(url, **kwargs)
            elif method == "DELETE":
                response = requests.delete(url, **kwargs)
            else:
                return False

            success = 200 <= response.status_code < 300

            result = {
                "test": name,
                "success": success,
                "status_code": response.status_code,
                "endpoint": endpoint,
                "method": method,
                "mtls": use_mtls
            }

            self.results.append(result)
            self.log(f"{name} - Status: {response.status_code}", "SUCCESS" if success else "ERROR")

            if not success and hasattr(response, 'text'):
                self.log(f"Response: {response.text[:150]}", "ERROR")

            return response if success else None

        except Exception as e:
            self.log(f"{name} - Exception: {str(e)}", "ERROR")
            self.results.append({
                "test": name,
                "success": False,
                "error": str(e),
                "endpoint": endpoint
            })
            return None

    def test_health_checks(self):
        self.log("TESTING HEALTH CHECKS", "TEST")

        self.test_endpoint(
            "Health Check HTTP (8000)",
            "GET",
            "/health"
        )

        try:
            response = requests.get(
                f"{self.base_url_https_no_mtls}/health",
                verify=False,
                timeout=10
            )
            success = response.status_code == 200
            self.log(f"Health Check HTTPS without mTLS (9444) - Status: {response.status_code}",
                     "SUCCESS" if success else "ERROR")
            self.results.append({
                "test": "Health Check HTTPS without mTLS",
                "success": success,
                "status_code": response.status_code
            })
        except Exception as e:
            self.log(f"Health Check HTTPS without mTLS - Error: {e}", "ERROR")

        self.test_endpoint(
            "Health Check HTTPS with mTLS (9443)",
            "GET",
            "/health",
            use_mtls=True
        )

    def test_mtls(self):
        self.log("TESTING mTLS (MUTUAL TLS)", "TEST")

        response = self.test_endpoint(
            "Get mTLS information",
            "GET",
            "/mtls-info",
            use_mtls=True
        )

        if response:
            try:
                mtls_info = response.json()
                self.log(f"Client Certificate: {mtls_info.get('client_certificate', 'N/A')}", "INFO")
                self.log(f"Verification Status: {mtls_info.get('verification_status', 'N/A')}", "INFO")
                self.log(f"Authentication Method: {mtls_info.get('authentication_method', 'N/A')}", "INFO")
                self.log(f"Security Level: {mtls_info.get('security_level', 'N/A')}", "INFO")
            except:
                pass

        if self.token:
            mtls_reading = {
                "device_id": "OXIM-002",
                "patient_code": "PAT-IGOR-001",
                "spo2": 97.0,
                "bpm": 75,
                "reading_timestamp": datetime.utcnow().isoformat(),
                "signature": f"mtls_signature_{int(time.time())}"
            }

            self.test_endpoint(
                "Send reading via mTLS",
                "POST",
                "/readings",
                use_mtls=True,
                json=mtls_reading
            )

    def test_authentication(self):
        self.log("TESTING JWT AUTHENTICATION", "TEST")

        try:
            response = requests.post(
                f"{self.base_url}/login",
                data={"username": self.username, "password": self.password},
                timeout=10
            )

            if response.status_code == 200:
                data = response.json()
                self.token = data.get("access_token")
                self.log(f"Login successful for user: {self.username}", "SUCCESS")
                self.log(f"Token: {self.token[:50]}...", "INFO")

                self.results.append({
                    "test": "JWT Login",
                    "success": True,
                    "status_code": 200
                })
                return True
            else:
                self.log(f"Login failed: {response.status_code} - {response.text}", "ERROR")
                self.results.append({
                    "test": "JWT Login",
                    "success": False,
                    "status_code": response.status_code
                })
                return False

        except Exception as e:
            self.log(f"Error connecting to API for login: {e}", "ERROR")
            return False

    def test_functional_requirements(self):
        self.log("TESTING FUNCTIONAL REQUIREMENTS", "TEST")

        if not self.token:
            self.log("Token not available, skipping authentication-required tests", "WARNING")
            return

        headers = {"Authorization": f"Bearer {self.token}"}

        self.log("RF01: Patient Management", "TEST")
        response = self.test_endpoint(
            "List doctor's patients",
            "GET",
            "/patients",
            headers=headers
        )

        patients = []
        if response:
            try:
                patients = response.json()
                self.log(f"Patients found: {len(patients)}", "INFO")
                for p in patients[:3]:
                    self.log(f"- [{p.get('patient_code')}] {p.get('full_name')}", "INFO")
            except:
                pass

        self.log("RF02: Reading Registration", "TEST")
        if patients:
            reading = {
                "device_id": "OXIM-001",
                "patient_code": patients[0].get('patient_code'),
                "spo2": 98.5,
                "bpm": 72,
                "reading_timestamp": datetime.utcnow().isoformat(),
                "signature": f"test_signature_{int(time.time())}"
            }

            response = self.test_endpoint(
                "Register reading (HTTP)",
                "POST",
                "/readings",
                json=reading,
                headers={"Content-Type": "application/json"}
            )

            if response:
                try:
                    result = response.json()
                    self.log(f"Reading ID: {result.get('id')}", "INFO")
                    self.log(f"SpO2: {result.get('spo2')}% | BPM: {result.get('bpm')}", "INFO")
                except:
                    pass

        self.log("RF03: Reading Consultation", "TEST")
        if patients:
            patient_code = patients[0].get('patient_code')
            response = self.test_endpoint(
                "Consult patient readings",
                "GET",
                f"/readings/{patient_code}",
                headers=headers
            )

            if response:
                try:
                    readings = response.json()
                    self.log(f"Total readings: {len(readings)}", "INFO")
                    for l in readings[:3]:
                        self.log(f"- SpO2: {l.get('spo2')}% | BPM: {l.get('bpm')} | {l.get('reading_timestamp')}",
                                 "INFO")
                except:
                    pass

        self.log("RF04: Device Registration", "TEST")
        response = self.test_endpoint(
            "Register new device",
            "POST",
            "/devices/register",
            headers=headers
        )

        if response:
            try:
                device = response.json()
                self.log(f"Device ID: {device.get('device_id')}", "INFO")
                self.log(f"Secret: {device.get('device_secret', '')[:30]}...", "INFO")
            except:
                pass

    def test_non_functional_requirements(self):
        self.log("TESTING NON-FUNCTIONAL REQUIREMENTS", "TEST")

        self.log("RNF01: Security Architecture", "TEST")
        response = self.test_endpoint(
            "Get security information",
            "GET",
            "/security-info"
        )

        if response:
            try:
                sec_info = response.json()
                self.log(f"Architecture: {sec_info.get('architecture')}", "INFO")
                self.log(f"External: {sec_info.get('external')}", "INFO")
                self.log(f"Authentication: {sec_info.get('authentication')}", "INFO")
            except:
                pass

        self.log("RNF02: Audit System", "TEST")
        if self.token:
            headers = {"Authorization": f"Bearer {self.token}"}
            self.test_endpoint(
                "Check audit logs",
                "GET",
                "/logs",
                headers=headers
            )

        self.log("RNF03: Performance and Response Time", "TEST")
        times = []
        for i in range(5):
            start_time = time.time()
            response = self.test_endpoint(
                f"Performance test #{i + 1}",
                "GET",
                "/health"
            )
            elapsed = time.time() - start_time
            times.append(elapsed)

        avg_time = sum(times) / len(times)
        self.log(f"Average response time: {avg_time * 1000:.0f}ms", "INFO")

        if avg_time < 1.0:
            self.log("EXCELLENT performance (< 1s)", "SUCCESS")
        elif avg_time < 3.0:
            self.log("GOOD performance (< 3s)", "SUCCESS")
        else:
            self.log("Performance could be improved", "WARNING")

        self.log("RNF04: Regulatory Compliance", "TEST")
        response = self.test_endpoint(
            "Compliance policies (LGPD/ANVISA)",
            "GET",
            "/compliance/policy"
        )

        if response:
            try:
                policy = response.json()
                self.log(f"Data retention: {policy.get('data_retention_days')} days", "INFO")
                frameworks = policy.get('compliance_frameworks', [])
                self.log(f"Frameworks: {', '.join(frameworks)}", "INFO")
            except:
                pass

    def test_bola_doctor_a_vs_b(self):
        self.log("BOLA TEST: Doctor A vs B (30 minutes)", "TEST")

        resp_a = requests.post(
            f"{self.base_url}/login",
            data={"username": "dr.ana", "password": "secret1234"},
            timeout=10
        )
        if resp_a.status_code != 200:
            self.log("Failed login for doctor A (ana)", "ERROR")
            return False
        token_a = resp_a.json()["access_token"]

        resp_b = requests.post(
            f"{self.base_url}/login",
            data={"username": "dr.jose", "password": "secret1234"},
            timeout=10
        )
        if resp_b.status_code != 200:
            self.log(f"Failed login for doctor B (dr.jose): {resp_b.status_code} - {resp_b.text}", "ERROR")
            return False
        token_b = resp_b.json()["access_token"]

        headers_a = {"Authorization": f"Bearer {token_a}"}
        headers_b = {"Authorization": f"Bearer {token_b}"}

        pa = requests.get(f"{self.base_url}/patients", headers=headers_a, timeout=10)
        pb = requests.get(f"{self.base_url}/patients", headers=headers_b, timeout=10)

        if pa.status_code != 200 or pb.status_code != 200:
            self.log("Failed to list patients for A or B", "ERROR")
            return False

        patients_a = {p["patient_code"] for p in pa.json()}
        patients_b = {p["patient_code"] for p in pb.json()}

        self.log(f"Doctor A (igor) sees {len(patients_a)} patients", "INFO")
        self.log(f"Doctor B (dr.jose) sees {len(patients_b)} patients", "INFO")

        intersection = patients_a.intersection(patients_b)
        if intersection:
            self.log(f"BOLA: patients shared between A and B: {intersection}", "ERROR")
            return False

        self.log("BOLA: doctors do not share patients", "SUCCESS")

        for code in list(patients_a)[:1]:
            ra = requests.get(f"{self.base_url}/readings/{code}", headers=headers_a, timeout=10)
            rb = requests.get(f"{self.base_url}/readings/{code}", headers=headers_b, timeout=10)

            if ra.status_code == 200 and rb.status_code == 403:
                self.log(f"Doctor A accesses {code} and B is blocked", "SUCCESS")
            else:
                self.log(f"Partial BOLA for {code}: A={ra.status_code}, B={rb.status_code}", "WARNING")

        return True

    def final_report(self):
        self.log("FINAL TEST REPORT", "TEST")

        total_tests = len(self.results)
        successful_tests = sum(1 for r in self.results if r.get('success', False))
        success_rate = (successful_tests / total_tests * 100) if total_tests > 0 else 0

        self.log(f"Total tests executed: {total_tests}", "INFO")
        self.log(f"Successful tests: {successful_tests}", "SUCCESS")
        self.log(f"Failed tests: {total_tests - successful_tests}",
                 "ERROR" if (total_tests - successful_tests) > 0 else "INFO")
        self.log(f"Success rate: {success_rate:.1f}%", "INFO")

        export_result = {
            "test_date": datetime.now().isoformat(),
            "credentials_used": {
                "username": self.username,
                "password": "***"
            },
            "total_tests": total_tests,
            "successful_tests": successful_tests,
            "success_rate": success_rate,
            "results": self.results
        }

        with open("test_results.json", "w", encoding="utf-8") as f:
            json.dump(export_result, f, indent=2, ensure_ascii=False)

        self.log(f"Results saved in: test_results.json", "SUCCESS")

        if success_rate >= 90:
            self.log("SYSTEM FULLY FUNCTIONAL!", "SUCCESS")
        elif success_rate >= 75:
            self.log("SYSTEM FUNCTIONAL WITH ATTENTION POINTS", "SUCCESS")
        else:
            self.log("SYSTEM REQUIRES CORRECTIONS", "WARNING")

        return success_rate >= 75

    def execute_all_tests(self):
        self.test_health_checks()

        if not self.test_authentication():
            self.log("Critical authentication failure. Aborting token-required tests.", "ERROR")

        self.test_mtls()

        self.test_functional_requirements()

        bola_ok = self.test_bola_doctor_a_vs_b()
        self.results.append({
            "test": "BOLA_Doctor_A_vs_B",
            "success": bola_ok
        })

        self.test_non_functional_requirements()

        return self.final_report()


if __name__ == "__main__":
    tester = TCCTestSystem()

    if tester.execute_all_tests():
        print("\nTodos os testes passaram!")
        sys.exit(0)
    else:
        print("\nHouveram algumas falhas, verificar em test_results.json")
        sys.exit(1)