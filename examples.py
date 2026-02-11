#!/usr/bin/env python3
"""
MSTT 사용 예제 및 데모
Example Usage for Mahalanobis Security Testing Toolkit
"""

from mstt import (
    BlackboxTester, WhiteboxTester, GreyboxTester,
    ReportGenerator
)
import numpy as np
import json


# ============================================================================
# Example 1: Blackbox Testing - API Security
# ============================================================================

def example_blackbox_api_security():
    """블랙박스 예제: API 보안 테스트"""
    print("\n" + "="*80)
    print("EXAMPLE 1: BLACKBOX TESTING - API Security")
    print("="*80)
    
    # 정상 API 트래픽 패턴 (학습 데이터)
    normal_traffic = [
        {'request_rate': 10, 'payload_size': 1024, 'response_time': 0.2, 'error_rate': 0.01},
        {'request_rate': 12, 'payload_size': 1200, 'response_time': 0.25, 'error_rate': 0.02},
        {'request_rate': 8, 'payload_size': 900, 'response_time': 0.18, 'error_rate': 0.01},
        {'request_rate': 15, 'payload_size': 1500, 'response_time': 0.3, 'error_rate': 0.03},
        {'request_rate': 11, 'payload_size': 1100, 'response_time': 0.22, 'error_rate': 0.015},
        {'request_rate': 9, 'payload_size': 950, 'response_time': 0.19, 'error_rate': 0.012},
        {'request_rate': 13, 'payload_size': 1300, 'response_time': 0.27, 'error_rate': 0.025},
        {'request_rate': 10, 'payload_size': 1050, 'response_time': 0.21, 'error_rate': 0.018},
    ]
    
    # 테스트 데이터 (정상 + 공격 패턴)
    test_traffic = [
        # 정상 트래픽
        {'request_rate': 11, 'payload_size': 1150, 'response_time': 0.23, 'error_rate': 0.02},
        {'request_rate': 9, 'payload_size': 980, 'response_time': 0.19, 'error_rate': 0.015},
        
        # DDoS 공격 (높은 request_rate)
        {'request_rate': 500, 'payload_size': 1200, 'response_time': 5.0, 'error_rate': 0.5},
        
        # SQL Injection 시도 (큰 payload, 높은 error_rate)
        {'request_rate': 15, 'payload_size': 50000, 'response_time': 0.8, 'error_rate': 0.9},
        
        # Brute Force (높은 request_rate, 높은 error_rate)
        {'request_rate': 100, 'payload_size': 500, 'response_time': 0.1, 'error_rate': 0.95},
        
        # 정상
        {'request_rate': 12, 'payload_size': 1100, 'response_time': 0.24, 'error_rate': 0.018},
    ]
    
    # 블랙박스 테스터 초기화 및 학습
    tester = BlackboxTester(confidence=0.95)
    tester.collect_baseline(normal_traffic)
    
    # 테스트 실행
    result = tester.test(test_traffic, target_name="API Gateway")
    
    # 리포트 생성
    ReportGenerator.generate_console_report(result)
    ReportGenerator.generate_json_report(result, "blackbox_api_report.json")
    ReportGenerator.generate_html_report(result, "blackbox_api_report.html")
    
    return result


# ============================================================================
# Example 2: Whitebox Testing - Code Vulnerability Analysis
# ============================================================================

def example_whitebox_code_analysis():
    """화이트박스 예제: 코드 취약점 분석"""
    print("\n" + "="*80)
    print("EXAMPLE 2: WHITEBOX TESTING - Code Vulnerability Analysis")
    print("="*80)
    
    # 정상 코드 메트릭 (여러 함수/모듈의 메트릭)
    code_metrics = {
        'cyclomatic_complexity': [5, 6, 4, 7, 5, 6, 5, 4],  # 순환 복잡도
        'input_validation_score': [9, 8, 9, 7, 8, 9, 8, 9],  # 입력 검증 점수
        'memory_safety_score': [8, 9, 8, 8, 9, 8, 9, 8],     # 메모리 안전성
        'auth_check_coverage': [10, 9, 10, 8, 9, 10, 9, 10], # 인증 체크 커버리지
    }
    
    # 테스트 벡터 (정상 코드 + 취약 코드)
    test_vectors = [
        # 정상 코드
        {'cyclomatic_complexity': 5, 'input_validation_score': 9, 
         'memory_safety_score': 8, 'auth_check_coverage': 10},
        
        {'cyclomatic_complexity': 6, 'input_validation_score': 8, 
         'memory_safety_score': 9, 'auth_check_coverage': 9},
        
        # 취약점 1: 입력 검증 부족
        {'cyclomatic_complexity': 5, 'input_validation_score': 2, 
         'memory_safety_score': 8, 'auth_check_coverage': 9},
        
        # 취약점 2: 복잡도 높고 메모리 안전성 낮음
        {'cyclomatic_complexity': 25, 'input_validation_score': 7, 
         'memory_safety_score': 3, 'auth_check_coverage': 8},
        
        # 취약점 3: 인증 체크 누락
        {'cyclomatic_complexity': 6, 'input_validation_score': 8, 
         'memory_safety_score': 8, 'auth_check_coverage': 2},
        
        # 정상
        {'cyclomatic_complexity': 4, 'input_validation_score': 9, 
         'memory_safety_score': 9, 'auth_check_coverage': 10},
    ]
    
    # 화이트박스 테스터 초기화
    tester = WhiteboxTester(confidence=0.95)
    tester.analyze_code_structure(code_metrics)
    
    # 테스트 실행
    result = tester.test_vulnerability(test_vectors, target_name="Authentication Module")
    
    # 패치 권장사항 생성
    print("\n" + "-"*80)
    print("PATCH RECOMMENDATIONS:")
    print("-"*80)
    for i, event in enumerate(result.details):
        if event.is_anomaly:
            recommendations = tester.generate_patch_recommendations(event)
            print(f"\nVulnerability #{i+1} ({event.severity}):")
            print(f"  Problem: {recommendations['problem_area']}")
            print(f"  Action: {recommendations['action']}")
    
    # 리포트 생성
    ReportGenerator.generate_console_report(result)
    ReportGenerator.generate_json_report(result, "whitebox_code_report.json")
    ReportGenerator.generate_html_report(result, "whitebox_code_report.html")
    
    return result


# ============================================================================
# Example 3: Greybox Testing - Web Application Penetration Testing
# ============================================================================

def example_greybox_webapp():
    """그레이박스 예제: 웹 애플리케이션 침투 테스트"""
    print("\n" + "="*80)
    print("EXAMPLE 3: GREYBOX TESTING - Web Application Penetration Test")
    print("="*80)
    
    # 정상 웹 트래픽 (블랙박스 베이스라인)
    normal_traffic = [
        {'request_rate': 5, 'session_duration': 300, 'pages_visited': 10, 'form_submissions': 2},
        {'request_rate': 8, 'session_duration': 450, 'pages_visited': 15, 'form_submissions': 3},
        {'request_rate': 6, 'session_duration': 380, 'pages_visited': 12, 'form_submissions': 2},
        {'request_rate': 7, 'session_duration': 420, 'pages_visited': 13, 'form_submissions': 4},
        {'request_rate': 5, 'session_duration': 290, 'pages_visited': 9, 'form_submissions': 1},
        {'request_rate': 9, 'session_duration': 480, 'pages_visited': 16, 'form_submissions': 3},
        {'request_rate': 6, 'session_duration': 350, 'pages_visited': 11, 'form_submissions': 2},
        {'request_rate': 7, 'session_duration': 400, 'pages_visited': 14, 'form_submissions': 3},
    ]
    
    # 코드 메트릭 (화이트박스 정보 - 선택적)
    code_metrics = {
        'request_rate': [5, 8, 6, 7, 5, 9, 6, 7],
        'session_duration': [300, 450, 380, 420, 290, 480, 350, 400],
        'pages_visited': [10, 15, 12, 13, 9, 16, 11, 14],
        'form_submissions': [2, 3, 2, 4, 1, 3, 2, 3],
    }
    
    # 테스트 데이터 (정상 사용 + 공격 시나리오)
    test_data = [
        # 정상 사용자
        {'request_rate': 6, 'session_duration': 360, 'pages_visited': 12, 'form_submissions': 2},
        {'request_rate': 7, 'session_duration': 410, 'pages_visited': 13, 'form_submissions': 3},
        
        # 공격 1: 자동화된 크롤링 (높은 request_rate, 많은 페이지)
        {'request_rate': 50, 'session_duration': 120, 'pages_visited': 200, 'form_submissions': 0},
        
        # 공격 2: 폼 스팸 (많은 form_submissions)
        {'request_rate': 20, 'session_duration': 60, 'pages_visited': 5, 'form_submissions': 50},
        
        # 공격 3: 세션 하이재킹 (비정상적인 패턴)
        {'request_rate': 30, 'session_duration': 30, 'pages_visited': 50, 'form_submissions': 10},
        
        # 정상
        {'request_rate': 8, 'session_duration': 440, 'pages_visited': 14, 'form_submissions': 3},
    ]
    
    # 그레이박스 테스터 초기화
    tester = GreyboxTester(confidence=0.95)
    tester.setup(
        baseline_observations=normal_traffic,
        code_metrics=code_metrics  # 부분적 코드 정보 활용
    )
    
    # 테스트 실행 (3단계 자동)
    result = tester.test(test_data, target_name="Web Application")
    
    # 리포트 생성
    ReportGenerator.generate_console_report(result)
    ReportGenerator.generate_json_report(result, "greybox_webapp_report.json")
    ReportGenerator.generate_html_report(result, "greybox_webapp_report.html")
    
    return result


# ============================================================================
# Example 4: Network Intrusion Detection (IDS)
# ============================================================================

def example_network_ids():
    """네트워크 침입 탐지 예제"""
    print("\n" + "="*80)
    print("EXAMPLE 4: Network Intrusion Detection System (IDS)")
    print("="*80)
    
    # 정상 네트워크 트래픽
    normal_traffic = [
        {'packet_rate': 100, 'avg_packet_size': 512, 'connection_duration': 10, 'port_diversity': 5},
        {'packet_rate': 120, 'avg_packet_size': 480, 'connection_duration': 15, 'port_diversity': 6},
        {'packet_rate': 90, 'avg_packet_size': 550, 'connection_duration': 12, 'port_diversity': 4},
        {'packet_rate': 110, 'avg_packet_size': 500, 'connection_duration': 11, 'port_diversity': 5},
        {'packet_rate': 105, 'avg_packet_size': 520, 'connection_duration': 13, 'port_diversity': 5},
        {'packet_rate': 115, 'avg_packet_size': 490, 'connection_duration': 14, 'port_diversity': 6},
        {'packet_rate': 95, 'avg_packet_size': 530, 'connection_duration': 10, 'port_diversity': 4},
        {'packet_rate': 100, 'avg_packet_size': 510, 'connection_duration': 12, 'port_diversity': 5},
    ]
    
    # 공격 트래픽 포함 테스트
    test_traffic = [
        # 정상
        {'packet_rate': 105, 'avg_packet_size': 515, 'connection_duration': 11, 'port_diversity': 5},
        
        # DDoS 공격
        {'packet_rate': 10000, 'avg_packet_size': 64, 'connection_duration': 0.1, 'port_diversity': 1},
        
        # Port Scan
        {'packet_rate': 500, 'avg_packet_size': 40, 'connection_duration': 0.5, 'port_diversity': 1000},
        
        # 정상
        {'packet_rate': 110, 'avg_packet_size': 505, 'connection_duration': 13, 'port_diversity': 5},
        
        # Slow Attack (L7)
        {'packet_rate': 5, 'avg_packet_size': 1000, 'connection_duration': 3600, 'port_diversity': 1},
    ]
    
    # 블랙박스 테스터 (IDS는 일반적으로 블랙박스)
    tester = BlackboxTester(confidence=0.99)  # 높은 신뢰도
    tester.collect_baseline(normal_traffic)
    
    result = tester.test(test_traffic, target_name="Network Perimeter")
    
    # 리포트
    ReportGenerator.generate_console_report(result)
    ReportGenerator.generate_json_report(result, "network_ids_report.json")
    ReportGenerator.generate_html_report(result, "network_ids_report.html")
    
    return result


# ============================================================================
# Example 5: User Behavior Analytics (UEBA)
# ============================================================================

def example_ueba():
    """사용자 행동 분석 예제"""
    print("\n" + "="*80)
    print("EXAMPLE 5: User and Entity Behavior Analytics (UEBA)")
    print("="*80)
    
    # 정상 사용자 행동 (특정 사용자의 평소 패턴)
    normal_behavior = [
        {'login_time': 9, 'data_access_mb': 50, 'privileged_actions': 2, 'failed_attempts': 0},
        {'login_time': 9, 'data_access_mb': 45, 'privileged_actions': 1, 'failed_attempts': 0},
        {'login_time': 10, 'data_access_mb': 60, 'privileged_actions': 3, 'failed_attempts': 1},
        {'login_time': 9, 'data_access_mb': 55, 'privileged_actions': 2, 'failed_attempts': 0},
        {'login_time': 8, 'data_access_mb': 48, 'privileged_actions': 1, 'failed_attempts': 0},
        {'login_time': 9, 'data_access_mb': 52, 'privileged_actions': 2, 'failed_attempts': 0},
        {'login_time': 10, 'data_access_mb': 58, 'privileged_actions': 2, 'failed_attempts': 1},
        {'login_time': 9, 'data_access_mb': 50, 'privileged_actions': 1, 'failed_attempts': 0},
    ]
    
    # 테스트: 정상 + 내부자 위협
    test_behavior = [
        # 정상
        {'login_time': 9, 'data_access_mb': 53, 'privileged_actions': 2, 'failed_attempts': 0},
        
        # 내부자 위협 1: 비정상 시간대 + 대량 데이터 접근
        {'login_time': 2, 'data_access_mb': 5000, 'privileged_actions': 50, 'failed_attempts': 0},
        
        # 내부자 위협 2: 많은 실패 시도 (권한 상승 시도)
        {'login_time': 9, 'data_access_mb': 100, 'privileged_actions': 100, 'failed_attempts': 50},
        
        # 정상
        {'login_time': 10, 'data_access_mb': 57, 'privileged_actions': 2, 'failed_attempts': 1},
        
        # 계정 탈취 의심: 비정상 패턴
        {'login_time': 23, 'data_access_mb': 1000, 'privileged_actions': 20, 'failed_attempts': 5},
    ]
    
    tester = BlackboxTester(confidence=0.95)
    tester.collect_baseline(normal_behavior)
    
    result = tester.test(test_behavior, target_name="User: john.doe@company.com")
    
    ReportGenerator.generate_console_report(result)
    ReportGenerator.generate_json_report(result, "ueba_report.json")
    ReportGenerator.generate_html_report(result, "ueba_report.html")
    
    return result


# ============================================================================
# Main Execution
# ============================================================================

def main():
    """모든 예제 실행"""
    print("\n🔒 MSTT - Security Testing Examples")
    print("Choose an example to run:")
    print("  1. Blackbox - API Security Testing")
    print("  2. Whitebox - Code Vulnerability Analysis")
    print("  3. Greybox - Web Application Penetration Testing")
    print("  4. Network IDS - Intrusion Detection")
    print("  5. UEBA - User Behavior Analytics")
    print("  6. Run ALL examples")
    print("  0. Exit")
    
    choice = input("\nEnter choice (0-6): ").strip()
    
    if choice == '1':
        example_blackbox_api_security()
    elif choice == '2':
        example_whitebox_code_analysis()
    elif choice == '3':
        example_greybox_webapp()
    elif choice == '4':
        example_network_ids()
    elif choice == '5':
        example_ueba()
    elif choice == '6':
        print("\n🚀 Running ALL examples...\n")
        example_blackbox_api_security()
        example_whitebox_code_analysis()
        example_greybox_webapp()
        example_network_ids()
        example_ueba()
        print("\n✅ All examples completed!")
        print("\nGenerated reports:")
        print("  - blackbox_api_report.html/json")
        print("  - whitebox_code_report.html/json")
        print("  - greybox_webapp_report.html/json")
        print("  - network_ids_report.html/json")
        print("  - ueba_report.html/json")
    elif choice == '0':
        print("Goodbye!")
        return
    else:
        print("Invalid choice!")


if __name__ == "__main__":
    main()
