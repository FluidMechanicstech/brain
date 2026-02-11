#!/usr/bin/env python3
"""
Mahalanobis Security Testing Toolkit (MSTT)
===========================================
완전한 그레이박스/블랙박스/화이트박스 보안 테스팅 도구

Author: Security Research Team
Version: 1.0.0
License: MIT
"""

import numpy as np
import json
import time
import hashlib
import re
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass, asdict
from scipy.stats import chi2
import warnings
warnings.filterwarnings('ignore')


# ============================================================================
# Core: Mahalanobis Distance Engine
# ============================================================================

class MahalanobisEngine:
    """마할라노비스 거리 기반 이상 탐지 엔진"""
    
    def __init__(self, epsilon=1e-8):
        self.mean = None
        self.cov = None
        self.cov_inv = None
        self.epsilon = epsilon
        self.n_features = None
        self.is_trained = False
        
    def fit(self, data: np.ndarray):
        """정상 데이터로 학습"""
        data = np.array(data)
        if data.ndim == 1:
            data = data.reshape(-1, 1)
        
        self.n_features = data.shape[1]
        self.mean = np.mean(data, axis=0)
        self.cov = np.cov(data.T)
        
        # 공분산이 스칼라인 경우 처리
        if self.cov.ndim == 0:
            self.cov = np.array([[self.cov]])
        
        # 역행렬 계산 (안전하게)
        try:
            # 정규화 추가 (수치 안정성)
            ridge = 1e-6
            self.cov_inv = np.linalg.inv(self.cov + ridge * np.eye(self.n_features))
        except np.linalg.LinAlgError:
            # 특이행렬인 경우 의사역행렬
            self.cov_inv = np.linalg.pinv(self.cov)
        
        self.is_trained = True
        return self
    
    def distance(self, x: np.ndarray) -> float:
        """마할라노비스 거리 계산"""
        if not self.is_trained:
            raise ValueError("Model not trained. Call fit() first.")
        
        x = np.array(x).flatten()
        diff = x - self.mean
        
        try:
            dist_squared = diff.T @ self.cov_inv @ diff
            return np.sqrt(max(0, dist_squared))  # 음수 방지
        except:
            return float('inf')
    
    def gradient(self, x: np.ndarray) -> np.ndarray:
        """그래디언트 계산 (화이트박스용)"""
        if not self.is_trained:
            raise ValueError("Model not trained.")
        
        x = np.array(x).flatten()
        diff = x - self.mean
        d = self.distance(x)
        
        if d < self.epsilon:
            return np.zeros_like(x)
        
        return (self.cov_inv @ diff) / d
    
    def numerator(self, x: np.ndarray) -> np.ndarray:
        """분자 부분 (선형) - 빠른 screening용"""
        if not self.is_trained:
            raise ValueError("Model not trained.")
        
        x = np.array(x).flatten()
        diff = x - self.mean
        return self.cov_inv @ diff
    
    def is_anomaly(self, x: np.ndarray, confidence: float = 0.95) -> bool:
        """이상치 판정"""
        dist = self.distance(x)
        threshold = np.sqrt(chi2.ppf(confidence, self.n_features))
        return dist > threshold
    
    def get_threshold(self, confidence: float = 0.95) -> float:
        """임계값 계산"""
        return np.sqrt(chi2.ppf(confidence, self.n_features))
    
    def save(self, filepath: str):
        """모델 저장"""
        data = {
            'mean': self.mean.tolist(),
            'cov': self.cov.tolist(),
            'n_features': self.n_features
        }
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)
    
    def load(self, filepath: str):
        """모델 로드"""
        with open(filepath, 'r') as f:
            data = json.load(f)
        
        self.mean = np.array(data['mean'])
        self.cov = np.array(data['cov'])
        self.n_features = data['n_features']
        
        # 역행렬 계산
        try:
            ridge = 1e-6
            self.cov_inv = np.linalg.inv(self.cov + ridge * np.eye(self.n_features))
        except:
            self.cov_inv = np.linalg.pinv(self.cov)
        
        self.is_trained = True
        return self


# ============================================================================
# Data Models
# ============================================================================

@dataclass
class SecurityEvent:
    """보안 이벤트 데이터 클래스"""
    timestamp: str
    event_type: str
    features: Dict[str, float]
    distance: float
    is_anomaly: bool
    severity: str
    details: Dict = None
    
    def to_dict(self):
        return asdict(self)


@dataclass
class TestResult:
    """테스트 결과"""
    test_type: str  # whitebox, blackbox, greybox
    target: str
    timestamp: str
    total_tests: int
    anomalies_detected: int
    severity_breakdown: Dict[str, int]
    details: List[SecurityEvent]
    summary: str


# ============================================================================
# Blackbox Testing Module
# ============================================================================

class BlackboxTester:
    """블랙박스 테스팅 모듈 - 외부 관찰만으로 이상 탐지"""
    
    def __init__(self, confidence: float = 0.95):
        self.engine = MahalanobisEngine()
        self.confidence = confidence
        self.baseline_data = []
        
    def collect_baseline(self, observations: List[Dict[str, float]], 
                        duration: int = None):
        """정상 행동 패턴 수집 (학습 데이터)"""
        print(f"[BLACKBOX] Collecting baseline data...")
        
        if not observations:
            raise ValueError("No observations provided")
        
        # 딕셔너리를 numpy 배열로 변환
        feature_names = list(observations[0].keys())
        data = []
        
        for obs in observations:
            row = [obs.get(fname, 0.0) for fname in feature_names]
            data.append(row)
        
        self.baseline_data = np.array(data)
        self.feature_names = feature_names
        
        # 모델 학습
        self.engine.fit(self.baseline_data)
        
        print(f"[BLACKBOX] Baseline learned: {len(observations)} samples")
        print(f"[BLACKBOX] Features: {', '.join(feature_names)}")
        
        return self
    
    def test(self, test_data: List[Dict[str, float]], 
             target_name: str = "Unknown") -> TestResult:
        """블랙박스 테스트 실행"""
        print(f"\n[BLACKBOX] Testing {target_name}...")
        
        results = []
        anomaly_count = 0
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        
        threshold = self.engine.get_threshold(self.confidence)
        
        for i, obs in enumerate(test_data):
            # 특징 벡터 생성
            features_vector = [obs.get(fname, 0.0) for fname in self.feature_names]
            
            # 거리 계산
            distance = self.engine.distance(features_vector)
            is_anomaly = distance > threshold
            
            # 심각도 판정
            if is_anomaly:
                anomaly_count += 1
                ratio = distance / threshold
                if ratio > 3:
                    severity = "critical"
                elif ratio > 2:
                    severity = "high"
                elif ratio > 1.5:
                    severity = "medium"
                else:
                    severity = "low"
                severity_counts[severity] += 1
            else:
                severity = "normal"
            
            # 이벤트 생성
            event = SecurityEvent(
                timestamp=datetime.now().isoformat(),
                event_type="blackbox_observation",
                features=obs,
                distance=float(distance),
                is_anomaly=is_anomaly,
                severity=severity,
                details={
                    'threshold': float(threshold),
                    'ratio': float(distance / threshold) if threshold > 0 else 0
                }
            )
            results.append(event)
            
            # 실시간 출력
            if is_anomaly:
                print(f"  [!] Test {i+1}: ANOMALY detected (D={distance:.3f}, severity={severity})")
        
        # 결과 요약
        summary = f"Detected {anomaly_count}/{len(test_data)} anomalies"
        
        return TestResult(
            test_type="blackbox",
            target=target_name,
            timestamp=datetime.now().isoformat(),
            total_tests=len(test_data),
            anomalies_detected=anomaly_count,
            severity_breakdown=severity_counts,
            details=results,
            summary=summary
        )


# ============================================================================
# Whitebox Testing Module
# ============================================================================

class WhiteboxTester:
    """화이트박스 테스팅 모듈 - 내부 구조 분석"""
    
    def __init__(self, confidence: float = 0.95):
        self.engine = MahalanobisEngine()
        self.confidence = confidence
        self.feature_names = []
        self.code_paths = {}
        
    def analyze_code_structure(self, code_metrics: Dict[str, List[float]]):
        """코드 구조 분석 및 정상 패턴 학습"""
        print(f"[WHITEBOX] Analyzing code structure...")
        
        self.feature_names = list(code_metrics.keys())
        
        # 메트릭을 행렬로 변환
        data = np.array([code_metrics[fname] for fname in self.feature_names]).T
        
        # 학습
        self.engine.fit(data)
        
        print(f"[WHITEBOX] Code structure analyzed")
        print(f"[WHITEBOX] Metrics: {', '.join(self.feature_names)}")
        
        # 공분산 분석
        print(f"\n[WHITEBOX] Correlation Analysis:")
        for i, f1 in enumerate(self.feature_names):
            for j, f2 in enumerate(self.feature_names):
                if i < j:
                    corr = self.engine.cov[i, j] / np.sqrt(
                        self.engine.cov[i, i] * self.engine.cov[j, j]
                    )
                    if abs(corr) > 0.5:
                        print(f"  {f1} <-> {f2}: {corr:.3f}")
        
        return self
    
    def test_vulnerability(self, test_vectors: List[Dict[str, float]], 
                          target_name: str = "Code") -> TestResult:
        """취약점 테스트"""
        print(f"\n[WHITEBOX] Testing {target_name} for vulnerabilities...")
        
        results = []
        anomaly_count = 0
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        
        threshold = self.engine.get_threshold(self.confidence)
        
        for i, vector in enumerate(test_vectors):
            # 특징 벡터
            features = [vector.get(fname, 0.0) for fname in self.feature_names]
            
            # 거리 및 그래디언트 계산
            distance = self.engine.distance(features)
            gradient = self.engine.gradient(features)
            
            is_anomaly = distance > threshold
            
            # 심각도 및 취약점 위치 분석
            if is_anomaly:
                anomaly_count += 1
                ratio = distance / threshold
                
                # 그래디언트로 가장 문제되는 메트릭 찾기
                grad_abs = np.abs(gradient)
                problem_idx = np.argmax(grad_abs)
                problem_metric = self.feature_names[problem_idx]
                
                if ratio > 3:
                    severity = "critical"
                elif ratio > 2:
                    severity = "high"
                elif ratio > 1.5:
                    severity = "medium"
                else:
                    severity = "low"
                severity_counts[severity] += 1
                
                # 수정 방향 제안
                fix_direction = -gradient
                
                details = {
                    'threshold': float(threshold),
                    'ratio': float(ratio),
                    'problem_metric': problem_metric,
                    'problem_value': float(gradient[problem_idx]),
                    'fix_direction': fix_direction.tolist(),
                    'gradient': gradient.tolist()
                }
                
                print(f"  [!] Vulnerability {i+1}: {severity.upper()}")
                print(f"      Problem metric: {problem_metric}")
                print(f"      Suggested fix direction: {fix_direction[problem_idx]:.3f}")
            else:
                severity = "normal"
                details = {'threshold': float(threshold)}
            
            event = SecurityEvent(
                timestamp=datetime.now().isoformat(),
                event_type="whitebox_analysis",
                features=vector,
                distance=float(distance),
                is_anomaly=is_anomaly,
                severity=severity,
                details=details
            )
            results.append(event)
        
        summary = f"Found {anomaly_count}/{len(test_vectors)} vulnerabilities"
        
        return TestResult(
            test_type="whitebox",
            target=target_name,
            timestamp=datetime.now().isoformat(),
            total_tests=len(test_vectors),
            anomalies_detected=anomaly_count,
            severity_breakdown=severity_counts,
            details=results,
            summary=summary
        )
    
    def generate_patch_recommendations(self, vulnerability: SecurityEvent) -> Dict:
        """패치 권장사항 생성"""
        if not vulnerability.is_anomaly:
            return {"status": "no_patch_needed"}
        
        fix_dir = vulnerability.details.get('fix_direction', [])
        problem_metric = vulnerability.details.get('problem_metric', 'unknown')
        
        recommendations = {
            'priority': vulnerability.severity,
            'problem_area': problem_metric,
            'fix_direction': fix_dir,
            'action': f"Adjust {problem_metric} by approximately {fix_dir[0]:.2f} units"
        }
        
        return recommendations


# ============================================================================
# Greybox Testing Module (통합)
# ============================================================================

class GreyboxTester:
    """그레이박스 테스팅 - 블랙박스 + 화이트박스 통합"""
    
    def __init__(self, confidence: float = 0.95):
        self.blackbox = BlackboxTester(confidence)
        self.whitebox = WhiteboxTester(confidence)
        self.confidence = confidence
        
    def setup(self, baseline_observations: List[Dict], 
             code_metrics: Dict[str, List[float]] = None):
        """초기 설정 - 블랙박스 베이스라인 + 화이트박스 코드 분석"""
        print("[GREYBOX] Setting up hybrid testing environment...")
        
        # 블랙박스 학습
        self.blackbox.collect_baseline(baseline_observations)
        
        # 화이트박스 학습 (선택적)
        if code_metrics:
            self.whitebox.analyze_code_structure(code_metrics)
            self.has_whitebox = True
        else:
            self.has_whitebox = False
            print("[GREYBOX] Running in blackbox-only mode")
        
        return self
    
    def test(self, test_data: List[Dict], target_name: str = "System") -> TestResult:
        """그레이박스 테스트 - 3단계 접근"""
        print(f"\n[GREYBOX] Multi-stage testing on {target_name}...")
        
        # Stage 1: 블랙박스 빠른 스캔
        print("\n=== Stage 1: Blackbox Rapid Scan ===")
        bb_result = self.blackbox.test(test_data, target_name)
        
        # Stage 2: 의심 케이스 추출
        suspicious_cases = [
            event for event in bb_result.details 
            if event.is_anomaly
        ]
        
        print(f"\n=== Stage 2: Suspicious Cases Identified: {len(suspicious_cases)} ===")
        
        # Stage 3: 화이트박스 정밀 분석 (가능한 경우)
        detailed_results = []
        if self.has_whitebox and suspicious_cases:
            print("\n=== Stage 3: Whitebox Deep Analysis ===")
            
            for event in suspicious_cases:
                # 그래디언트 계산으로 근본 원인 파악
                features = [event.features.get(k, 0) for k in self.blackbox.feature_names]
                gradient = self.whitebox.engine.gradient(features)
                
                # 가장 문제되는 feature 식별
                problem_idx = np.argmax(np.abs(gradient))
                problem_feature = self.blackbox.feature_names[problem_idx]
                
                event.details['whitebox_analysis'] = {
                    'problem_feature': problem_feature,
                    'gradient_magnitude': float(np.abs(gradient[problem_idx])),
                    'fix_recommendation': f"Focus on {problem_feature}"
                }
                
                print(f"  [ANALYSIS] Event severity={event.severity}")
                print(f"             Root cause: {problem_feature}")
        
        # 결과 통합
        return TestResult(
            test_type="greybox",
            target=target_name,
            timestamp=datetime.now().isoformat(),
            total_tests=bb_result.total_tests,
            anomalies_detected=bb_result.anomalies_detected,
            severity_breakdown=bb_result.severity_breakdown,
            details=bb_result.details,
            summary=f"Greybox: {bb_result.summary}, analyzed {len(suspicious_cases)} suspicious cases"
        )


# ============================================================================
# Report Generator
# ============================================================================

class ReportGenerator:
    """보안 테스트 리포트 생성기"""
    
    @staticmethod
    def generate_console_report(result: TestResult):
        """콘솔 리포트"""
        print("\n" + "="*80)
        print(f"SECURITY TEST REPORT - {result.test_type.upper()}")
        print("="*80)
        print(f"Target: {result.target}")
        print(f"Timestamp: {result.timestamp}")
        print(f"Test Type: {result.test_type}")
        print(f"\nRESULTS:")
        print(f"  Total Tests: {result.total_tests}")
        print(f"  Anomalies Detected: {result.anomalies_detected}")
        print(f"  Detection Rate: {result.anomalies_detected/result.total_tests*100:.1f}%")
        print(f"\nSEVERITY BREAKDOWN:")
        for severity, count in result.severity_breakdown.items():
            if count > 0:
                print(f"  {severity.upper()}: {count}")
        print(f"\nSUMMARY: {result.summary}")
        print("="*80)
    
    @staticmethod
    def generate_json_report(result: TestResult, filepath: str):
        """JSON 리포트"""
        report_data = {
            'test_type': result.test_type,
            'target': result.target,
            'timestamp': result.timestamp,
            'total_tests': result.total_tests,
            'anomalies_detected': result.anomalies_detected,
            'severity_breakdown': result.severity_breakdown,
            'summary': result.summary,
            'details': [event.to_dict() for event in result.details]
        }
        
        with open(filepath, 'w') as f:
            json.dump(report_data, f, indent=2)
        
        print(f"\n[REPORT] JSON report saved to: {filepath}")
    
    @staticmethod
    def generate_html_report(result: TestResult, filepath: str):
        """HTML 리포트"""
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Security Test Report - {result.target}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        h1 {{ color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; }}
        h2 {{ color: #34495e; margin-top: 30px; }}
        .summary {{ background: #ecf0f1; padding: 15px; border-radius: 5px; margin: 20px 0; }}
        .metric {{ display: inline-block; margin: 10px 20px 10px 0; }}
        .metric-label {{ font-weight: bold; color: #7f8c8d; }}
        .metric-value {{ font-size: 24px; color: #2c3e50; }}
        .severity-critical {{ color: #e74c3c; font-weight: bold; }}
        .severity-high {{ color: #e67e22; font-weight: bold; }}
        .severity-medium {{ color: #f39c12; font-weight: bold; }}
        .severity-low {{ color: #3498db; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
        th {{ background: #34495e; color: white; padding: 12px; text-align: left; }}
        td {{ padding: 10px; border-bottom: 1px solid #ecf0f1; }}
        tr:hover {{ background: #f8f9fa; }}
        .anomaly {{ background: #ffe6e6; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔒 Security Test Report</h1>
        
        <div class="summary">
            <div class="metric">
                <div class="metric-label">Target</div>
                <div class="metric-value">{result.target}</div>
            </div>
            <div class="metric">
                <div class="metric-label">Test Type</div>
                <div class="metric-value">{result.test_type.upper()}</div>
            </div>
            <div class="metric">
                <div class="metric-label">Total Tests</div>
                <div class="metric-value">{result.total_tests}</div>
            </div>
            <div class="metric">
                <div class="metric-label">Anomalies</div>
                <div class="metric-value severity-critical">{result.anomalies_detected}</div>
            </div>
        </div>
        
        <h2>Severity Breakdown</h2>
        <table>
            <tr>
                <th>Severity</th>
                <th>Count</th>
                <th>Percentage</th>
            </tr>
"""
        
        total = result.total_tests
        for severity, count in result.severity_breakdown.items():
            if count > 0:
                pct = count / total * 100
                html += f"""
            <tr>
                <td class="severity-{severity}">{severity.upper()}</td>
                <td>{count}</td>
                <td>{pct:.1f}%</td>
            </tr>
"""
        
        html += """
        </table>
        
        <h2>Detailed Findings</h2>
        <table>
            <tr>
                <th>#</th>
                <th>Timestamp</th>
                <th>Distance</th>
                <th>Severity</th>
                <th>Status</th>
            </tr>
"""
        
        for i, event in enumerate(result.details[:50], 1):  # 최대 50개만
            status = "ANOMALY" if event.is_anomaly else "Normal"
            row_class = "anomaly" if event.is_anomaly else ""
            html += f"""
            <tr class="{row_class}">
                <td>{i}</td>
                <td>{event.timestamp.split('T')[1][:8]}</td>
                <td>{event.distance:.3f}</td>
                <td class="severity-{event.severity}">{event.severity.upper()}</td>
                <td>{status}</td>
            </tr>
"""
        
        html += f"""
        </table>
        
        <div style="margin-top: 30px; padding: 15px; background: #e8f5e9; border-radius: 5px;">
            <strong>Summary:</strong> {result.summary}
        </div>
        
        <div style="margin-top: 20px; color: #7f8c8d; font-size: 12px;">
            Report generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
        </div>
    </div>
</body>
</html>
"""
        
        with open(filepath, 'w') as f:
            f.write(html)
        
        print(f"[REPORT] HTML report saved to: {filepath}")


# ============================================================================
# Main CLI
# ============================================================================

def print_banner():
    """배너 출력"""
    banner = """
╔══════════════════════════════════════════════════════════════════════╗
║                                                                      ║
║   ███╗   ███╗███████╗████████╗████████╗                            ║
║   ████╗ ████║██╔════╝╚══██╔══╝╚══██╔══╝                            ║
║   ██╔████╔██║███████╗   ██║      ██║                               ║
║   ██║╚██╔╝██║╚════██║   ██║      ██║                               ║
║   ██║ ╚═╝ ██║███████║   ██║      ██║                               ║
║   ╚═╝     ╚═╝╚══════╝   ╚═╝      ╚═╝                               ║
║                                                                      ║
║   Mahalanobis Security Testing Toolkit v1.0                         ║
║   Whitebox | Blackbox | Greybox Testing                             ║
║                                                                      ║
╚══════════════════════════════════════════════════════════════════════╝
"""
    print(banner)


if __name__ == "__main__":
    print_banner()
    print("\nToolkit loaded successfully!")
    print("Import this module to use in your security testing workflow.")
    print("\nExample usage:")
    print("  from mstt import BlackboxTester, WhiteboxTester, GreyboxTester")
    print("  tester = BlackboxTester()")
    print("  # ... your testing code ...")
