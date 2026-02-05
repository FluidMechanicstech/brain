"""
마할라노비스 거리와 비선형 편미분을 이용한 최적 경로 구현
Python Implementation

Author: Claude
Date: 2026-02-05
"""

import numpy as np
import matplotlib.pyplot as plt
from matplotlib.patches import Ellipse
from scipy.stats import chi2
import seaborn as sns

# 한글 폰트 설정 (선택사항)
plt.rcParams['font.family'] = 'DejaVu Sans'
plt.rcParams['axes.unicode_minus'] = False


# ============================================================================
# 1. 마할라노비스 거리 계산
# ============================================================================

class MahalanobisDistance:
    """마할라노비스 거리 계산 및 분석 클래스"""
    
    def __init__(self, mean, covariance):
        """
        Parameters:
        -----------
        mean : array-like, shape (n_features,)
            분포의 평균 벡터
        covariance : array-like, shape (n_features, n_features)
            공분산 행렬
        """
        self.mean = np.array(mean)
        self.cov = np.array(covariance)
        
        # 공분산 역행렬 계산 및 저장 (효율성)
        try:
            self.cov_inv = np.linalg.inv(self.cov)
        except np.linalg.LinAlgError:
            # 특이행렬인 경우 의사역행렬 사용
            print("Warning: Singular covariance matrix. Using pseudo-inverse.")
            self.cov_inv = np.linalg.pinv(self.cov)
    
    def distance(self, x):
        """
        마할라노비스 거리 계산
        
        Parameters:
        -----------
        x : array-like, shape (n_features,) or (n_samples, n_features)
            데이터 포인트
        
        Returns:
        --------
        distance : float or array
            마할라노비스 거리
        """
        x = np.array(x)
        
        if x.ndim == 1:
            # 단일 포인트
            diff = x - self.mean
            distance_squared = diff.T @ self.cov_inv @ diff
            return np.sqrt(distance_squared)
        else:
            # 여러 포인트
            diff = x - self.mean
            distances = []
            for d in diff:
                distance_squared = d.T @ self.cov_inv @ d
                distances.append(np.sqrt(distance_squared))
            return np.array(distances)
    
    def gradient(self, x, epsilon=1e-8):
        """
        마할라노비스 거리의 그래디언트 (편미분 벡터) 계산
        
        Parameters:
        -----------
        x : array-like, shape (n_features,)
            데이터 포인트
        epsilon : float
            0 나누기 방지를 위한 작은 값
        
        Returns:
        --------
        gradient : array, shape (n_features,)
            그래디언트 벡터
        """
        x = np.array(x)
        diff = x - self.mean
        d = self.distance(x)
        
        # 0 나누기 방지
        if d < epsilon:
            return np.zeros_like(x)
        
        # ∂D/∂x = Σ⁻¹(x-μ) / D
        gradient = (self.cov_inv @ diff) / d
        return gradient
    
    def is_outlier(self, x, confidence=0.95):
        """
        이상치 판정 (카이제곱 분포 기반)
        
        Parameters:
        -----------
        x : array-like
            데이터 포인트
        confidence : float
            신뢰수준 (기본값: 0.95)
        
        Returns:
        --------
        is_outlier : bool or array
            이상치 여부
        """
        distances = self.distance(x)
        n_features = len(self.mean)
        threshold = np.sqrt(chi2.ppf(confidence, n_features))
        
        return distances > threshold


# ============================================================================
# 2. 최적 경로 계산
# ============================================================================

def gradient_descent_path(md, start_point, learning_rate=0.1, 
                         max_iterations=100, tolerance=1e-3):
    """
    그래디언트 하강법으로 원점으로 가는 최적 경로 계산
    
    Parameters:
    -----------
    md : MahalanobisDistance
        마할라노비스 거리 객체
    start_point : array-like
        시작점
    learning_rate : float
        학습률
    max_iterations : int
        최대 반복 횟수
    tolerance : float
        수렴 기준
    
    Returns:
    --------
    path : array, shape (n_steps, n_features)
        경로 상의 점들
    distances : array, shape (n_steps,)
        각 점에서의 거리
    """
    path = [np.array(start_point)]
    distances = [md.distance(start_point)]
    
    current_point = np.array(start_point)
    
    for i in range(max_iterations):
        # 그래디언트 계산
        grad = md.gradient(current_point)
        
        # 그래디언트 하강 (반대 방향으로 이동)
        next_point = current_point - learning_rate * grad
        
        # 거리 계산
        dist = md.distance(next_point)
        
        path.append(next_point)
        distances.append(dist)
        
        # 수렴 확인
        if dist < tolerance:
            break
        
        current_point = next_point
    
    return np.array(path), np.array(distances)


def straight_line_path(start_point, end_point, n_steps=50):
    """
    직선 경로 생성 (유클리드)
    
    Parameters:
    -----------
    start_point : array-like
        시작점
    end_point : array-like
        끝점
    n_steps : int
        경로 상의 점 개수
    
    Returns:
    --------
    path : array, shape (n_steps, n_features)
        경로 상의 점들
    """
    start = np.array(start_point)
    end = np.array(end_point)
    
    t = np.linspace(0, 1, n_steps)
    path = start + np.outer(t, end - start)
    
    return path


def compute_path_length(path, metric='euclidean', md=None):
    """
    경로 길이 계산
    
    Parameters:
    -----------
    path : array, shape (n_steps, n_features)
        경로
    metric : str
        거리 척도 ('euclidean' 또는 'mahalanobis')
    md : MahalanobisDistance
        마할라노비스 거리 객체 (metric='mahalanobis'일 때 필요)
    
    Returns:
    --------
    length : float
        경로 길이
    """
    length = 0.0
    
    for i in range(len(path) - 1):
        if metric == 'euclidean':
            length += np.linalg.norm(path[i+1] - path[i])
        elif metric == 'mahalanobis':
            if md is None:
                raise ValueError("MahalanobisDistance object required for mahalanobis metric")
            diff = path[i+1] - path[i]
            dist_squared = diff.T @ md.cov_inv @ diff
            length += np.sqrt(dist_squared)
    
    return length


# ============================================================================
# 3. 시각화 함수
# ============================================================================

def plot_mahalanobis_contour(md, xlim=(-4, 4), ylim=(-4, 4), n_points=100):
    """
    마할라노비스 거리 등고선 플롯
    
    Parameters:
    -----------
    md : MahalanobisDistance
        마할라노비스 거리 객체
    xlim, ylim : tuple
        플롯 범위
    n_points : int
        그리드 점 개수
    """
    x = np.linspace(xlim[0], xlim[1], n_points)
    y = np.linspace(ylim[0], ylim[1], n_points)
    X, Y = np.meshgrid(x, y)
    
    Z = np.zeros_like(X)
    for i in range(X.shape[0]):
        for j in range(X.shape[1]):
            Z[i, j] = md.distance([X[i, j], Y[i, j]])
    
    plt.figure(figsize=(10, 8))
    
    # 등고선
    contours = plt.contourf(X, Y, Z, levels=20, cmap='YlOrRd', alpha=0.6)
    plt.colorbar(contours, label='Mahalanobis Distance')
    
    # 등고선 라인
    plt.contour(X, Y, Z, levels=10, colors='black', alpha=0.3, linewidths=0.5)
    
    # 평균점 표시
    plt.plot(md.mean[0], md.mean[1], 'b+', markersize=15, markeredgewidth=3, 
             label='Mean')
    
    plt.xlabel('X')
    plt.ylabel('Y')
    plt.title('Mahalanobis Distance Contour')
    plt.legend()
    plt.grid(True, alpha=0.3)
    plt.axis('equal')


def plot_gradient_field(md, xlim=(-4, 4), ylim=(-4, 4), n_arrows=15):
    """
    그래디언트 벡터장 플롯
    
    Parameters:
    -----------
    md : MahalanobisDistance
        마할라노비스 거리 객체
    xlim, ylim : tuple
        플롯 범위
    n_arrows : int
        화살표 개수 (한 축 방향)
    """
    x = np.linspace(xlim[0], xlim[1], n_arrows)
    y = np.linspace(ylim[0], ylim[1], n_arrows)
    X, Y = np.meshgrid(x, y)
    
    U = np.zeros_like(X)
    V = np.zeros_like(Y)
    
    for i in range(X.shape[0]):
        for j in range(X.shape[1]):
            point = [X[i, j], Y[i, j]]
            grad = md.gradient(point)
            U[i, j] = grad[0]
            V[i, j] = grad[1]
    
    plt.quiver(X, Y, U, V, alpha=0.6, color='green', scale=20)


def plot_optimal_paths(md, start_point, target_point=None, 
                       learning_rate=0.15, figsize=(15, 5)):
    """
    최적 경로 비교 시각화
    
    Parameters:
    -----------
    md : MahalanobisDistance
        마할라노비스 거리 객체
    start_point : array-like
        시작점
    target_point : array-like, optional
        목표점 (비교용)
    learning_rate : float
        그래디언트 하강 학습률
    """
    # 경로 계산
    grad_path, grad_distances = gradient_descent_path(
        md, start_point, learning_rate=learning_rate
    )
    
    if target_point is None:
        target_point = md.mean
    
    straight_path = straight_line_path(start_point, target_point)
    straight_distances = md.distance(straight_path)
    
    # 경로 길이 계산
    grad_length_euclidean = compute_path_length(grad_path, 'euclidean')
    grad_length_mahalanobis = compute_path_length(grad_path, 'mahalanobis', md)
    straight_length_euclidean = compute_path_length(straight_path, 'euclidean')
    straight_length_mahalanobis = compute_path_length(straight_path, 'mahalanobis', md)
    
    # 시각화
    fig, axes = plt.subplots(1, 3, figsize=figsize)
    
    # 1. 등고선과 경로
    ax = axes[0]
    x = np.linspace(-4, 4, 100)
    y = np.linspace(-4, 4, 100)
    X, Y = np.meshgrid(x, y)
    Z = np.zeros_like(X)
    for i in range(X.shape[0]):
        for j in range(X.shape[1]):
            Z[i, j] = md.distance([X[i, j], Y[i, j]])
    
    contours = ax.contourf(X, Y, Z, levels=20, cmap='YlOrRd', alpha=0.5)
    ax.contour(X, Y, Z, levels=10, colors='black', alpha=0.3, linewidths=0.5)
    
    # 경로 그리기
    ax.plot(grad_path[:, 0], grad_path[:, 1], 'g-', linewidth=2.5, 
            label='Gradient Path', marker='o', markersize=3)
    ax.plot(straight_path[:, 0], straight_path[:, 1], 'orange', 
            linewidth=2, linestyle='--', label='Straight Path')
    
    # 시작점, 끝점, 평균 표시
    ax.plot(start_point[0], start_point[1], 'r*', markersize=15, label='Start')
    ax.plot(target_point[0], target_point[1], 'mo', markersize=10, label='Target')
    ax.plot(md.mean[0], md.mean[1], 'b+', markersize=15, 
            markeredgewidth=3, label='Mean')
    
    ax.set_xlabel('X')
    ax.set_ylabel('Y')
    ax.set_title('Optimal Paths on Contour Map')
    ax.legend()
    ax.grid(True, alpha=0.3)
    ax.axis('equal')
    
    # 2. 거리 변화
    ax = axes[1]
    ax.plot(range(len(grad_distances)), grad_distances, 'g-', 
            linewidth=2, label='Gradient Path', marker='o', markersize=4)
    ax.plot(range(len(straight_distances)), straight_distances, 'orange', 
            linewidth=2, linestyle='--', label='Straight Path')
    ax.set_xlabel('Step')
    ax.set_ylabel('Mahalanobis Distance')
    ax.set_title('Distance Along Path')
    ax.legend()
    ax.grid(True, alpha=0.3)
    
    # 3. 경로 길이 비교
    ax = axes[2]
    categories = ['Gradient\nPath', 'Straight\nPath']
    euclidean_lengths = [grad_length_euclidean, straight_length_euclidean]
    mahalanobis_lengths = [grad_length_mahalanobis, straight_length_mahalanobis]
    
    x_pos = np.arange(len(categories))
    width = 0.35
    
    ax.bar(x_pos - width/2, euclidean_lengths, width, label='Euclidean', 
           color='skyblue')
    ax.bar(x_pos + width/2, mahalanobis_lengths, width, label='Mahalanobis', 
           color='salmon')
    
    ax.set_ylabel('Path Length')
    ax.set_title('Path Length Comparison')
    ax.set_xticks(x_pos)
    ax.set_xticklabels(categories)
    ax.legend()
    ax.grid(True, alpha=0.3, axis='y')
    
    plt.tight_layout()
    
    # 결과 출력
    print("=" * 60)
    print("Path Analysis Results")
    print("=" * 60)
    print(f"Start Point: {start_point}")
    print(f"Target Point: {target_point}")
    print(f"\nGradient Path:")
    print(f"  - Steps: {len(grad_path)}")
    print(f"  - Euclidean Length: {grad_length_euclidean:.3f}")
    print(f"  - Mahalanobis Length: {grad_length_mahalanobis:.3f}")
    print(f"  - Final Distance: {grad_distances[-1]:.3f}")
    print(f"\nStraight Path:")
    print(f"  - Euclidean Length: {straight_length_euclidean:.3f}")
    print(f"  - Mahalanobis Length: {straight_length_mahalanobis:.3f}")
    print("=" * 60)
    
    return grad_path, straight_path


def plot_gradient_field_on_contour(md, xlim=(-4, 4), ylim=(-4, 4), 
                                   n_contour=100, n_arrows=12):
    """
    등고선 위에 그래디언트 벡터장 오버레이
    
    Parameters:
    -----------
    md : MahalanobisDistance
        마할라노비스 거리 객체
    xlim, ylim : tuple
        플롯 범위
    n_contour : int
        등고선 그리드 점 개수
    n_arrows : int
        벡터장 화살표 개수
    """
    plt.figure(figsize=(12, 10))
    
    # 등고선
    x = np.linspace(xlim[0], xlim[1], n_contour)
    y = np.linspace(ylim[0], ylim[1], n_contour)
    X, Y = np.meshgrid(x, y)
    Z = np.zeros_like(X)
    for i in range(X.shape[0]):
        for j in range(X.shape[1]):
            Z[i, j] = md.distance([X[i, j], Y[i, j]])
    
    contours = plt.contourf(X, Y, Z, levels=20, cmap='YlOrRd', alpha=0.6)
    plt.colorbar(contours, label='Mahalanobis Distance')
    plt.contour(X, Y, Z, levels=10, colors='black', alpha=0.3, linewidths=0.5)
    
    # 그래디언트 벡터장
    x_arrows = np.linspace(xlim[0], xlim[1], n_arrows)
    y_arrows = np.linspace(ylim[0], ylim[1], n_arrows)
    X_arrows, Y_arrows = np.meshgrid(x_arrows, y_arrows)
    
    U = np.zeros_like(X_arrows)
    V = np.zeros_like(Y_arrows)
    
    for i in range(X_arrows.shape[0]):
        for j in range(X_arrows.shape[1]):
            point = [X_arrows[i, j], Y_arrows[i, j]]
            grad = md.gradient(point)
            U[i, j] = grad[0]
            V[i, j] = grad[1]
    
    plt.quiver(X_arrows, Y_arrows, U, V, alpha=0.7, color='green', 
               scale=25, width=0.003)
    
    # 평균점
    plt.plot(md.mean[0], md.mean[1], 'b+', markersize=20, 
             markeredgewidth=4, label='Mean')
    
    plt.xlabel('X')
    plt.ylabel('Y')
    plt.title('Mahalanobis Distance with Gradient Field')
    plt.legend()
    plt.grid(True, alpha=0.3)
    plt.axis('equal')


# ============================================================================
# 4. 이상치 탐지 예제
# ============================================================================

def outlier_detection_example(md, data, confidence=0.95):
    """
    이상치 탐지 시각화
    
    Parameters:
    -----------
    md : MahalanobisDistance
        마할라노비스 거리 객체
    data : array, shape (n_samples, n_features)
        데이터
    confidence : float
        신뢰수준
    """
    distances = md.distance(data)
    is_outlier = md.is_outlier(data, confidence)
    
    plt.figure(figsize=(12, 5))
    
    # 1. 산점도
    plt.subplot(1, 2, 1)
    
    # 등고선
    x = np.linspace(data[:, 0].min() - 1, data[:, 0].max() + 1, 100)
    y = np.linspace(data[:, 1].min() - 1, data[:, 1].max() + 1, 100)
    X, Y = np.meshgrid(x, y)
    Z = np.zeros_like(X)
    for i in range(X.shape[0]):
        for j in range(X.shape[1]):
            Z[i, j] = md.distance([X[i, j], Y[i, j]])
    
    plt.contour(X, Y, Z, levels=10, colors='gray', alpha=0.3)
    
    # 데이터 포인트
    plt.scatter(data[~is_outlier, 0], data[~is_outlier, 1], 
                c='blue', alpha=0.6, label='Normal', s=50)
    plt.scatter(data[is_outlier, 0], data[is_outlier, 1], 
                c='red', alpha=0.8, label='Outlier', s=100, marker='x')
    
    plt.plot(md.mean[0], md.mean[1], 'g+', markersize=15, 
             markeredgewidth=3, label='Mean')
    
    plt.xlabel('X')
    plt.ylabel('Y')
    plt.title(f'Outlier Detection (Confidence: {confidence*100:.0f}%)')
    plt.legend()
    plt.grid(True, alpha=0.3)
    plt.axis('equal')
    
    # 2. 거리 히스토그램
    plt.subplot(1, 2, 2)
    
    n_features = len(md.mean)
    threshold = np.sqrt(chi2.ppf(confidence, n_features))
    
    plt.hist(distances, bins=30, alpha=0.7, color='blue', edgecolor='black')
    plt.axvline(threshold, color='red', linestyle='--', linewidth=2, 
                label=f'Threshold ({confidence*100:.0f}%)')
    
    plt.xlabel('Mahalanobis Distance')
    plt.ylabel('Frequency')
    plt.title('Distance Distribution')
    plt.legend()
    plt.grid(True, alpha=0.3)
    
    plt.tight_layout()
    
    # 결과 출력
    print("=" * 60)
    print("Outlier Detection Results")
    print("=" * 60)
    print(f"Total samples: {len(data)}")
    print(f"Normal samples: {(~is_outlier).sum()}")
    print(f"Outliers: {is_outlier.sum()}")
    print(f"Outlier rate: {is_outlier.sum() / len(data) * 100:.2f}%")
    print(f"Threshold: {threshold:.3f}")
    print("=" * 60)


# ============================================================================
# 5. 메인 예제 실행
# ============================================================================

def main_example():
    """종합 예제 실행"""
    
    print("\n" + "=" * 60)
    print("Mahalanobis Distance and Optimal Path Analysis")
    print("=" * 60 + "\n")
    
    # 1. 마할라노비스 거리 객체 생성
    mean = np.array([0, 0])
    covariance = np.array([[1.5, 0.8],
                          [0.8, 1.0]])
    
    md = MahalanobisDistance(mean, covariance)
    
    print("Covariance Matrix:")
    print(covariance)
    print("\nCovariance Inverse:")
    print(md.cov_inv)
    print()
    
    # 2. 최적 경로 비교
    start_point = np.array([2.5, 2.5])
    target_point = np.array([-2.0, -1.5])
    
    print("Computing optimal paths...")
    grad_path, straight_path = plot_optimal_paths(
        md, start_point, target_point, learning_rate=0.15
    )
    plt.savefig('optimal_paths.png', dpi=150, bbox_inches='tight')
    print("Saved: optimal_paths.png\n")
    
    # 3. 그래디언트 벡터장과 등고선
    print("Plotting gradient field on contour map...")
    plot_gradient_field_on_contour(md)
    plt.savefig('gradient_field.png', dpi=150, bbox_inches='tight')
    print("Saved: gradient_field.png\n")
    
    # 4. 이상치 탐지 예제
    print("Generating sample data for outlier detection...")
    np.random.seed(42)
    
    # 정상 데이터
    normal_data = np.random.multivariate_normal(mean, covariance, 100)
    
    # 이상치 추가
    outliers = np.array([[4, 3], [-3, 4], [3, -3], [-4, -2]])
    data = np.vstack([normal_data, outliers])
    
    print("Running outlier detection...")
    outlier_detection_example(md, data, confidence=0.95)
    plt.savefig('outlier_detection.png', dpi=150, bbox_inches='tight')
    print("Saved: outlier_detection.png\n")
    
    # 5. 단일 점에 대한 분석
    test_point = np.array([2, 1.5])
    distance = md.distance(test_point)
    gradient = md.gradient(test_point)
    is_outlier_point = md.is_outlier(test_point, confidence=0.95)
    
    print("=" * 60)
    print("Single Point Analysis")
    print("=" * 60)
    print(f"Test Point: {test_point}")
    print(f"Mahalanobis Distance: {distance:.4f}")
    print(f"Gradient: {gradient}")
    print(f"Gradient Magnitude: {np.linalg.norm(gradient):.4f}")
    print(f"Is Outlier (95% confidence): {is_outlier_point}")
    print("=" * 60 + "\n")
    
    plt.show()


# ============================================================================
# 6. 추가 유틸리티 함수
# ============================================================================

def compare_multiple_starting_points(md, start_points, learning_rate=0.15):
    """
    여러 시작점에서 경로 비교
    
    Parameters:
    -----------
    md : MahalanobisDistance
        마할라노비스 거리 객체
    start_points : list of arrays
        시작점 리스트
    learning_rate : float
        학습률
    """
    plt.figure(figsize=(12, 10))
    
    # 등고선
    x = np.linspace(-4, 4, 100)
    y = np.linspace(-4, 4, 100)
    X, Y = np.meshgrid(x, y)
    Z = np.zeros_like(X)
    for i in range(X.shape[0]):
        for j in range(X.shape[1]):
            Z[i, j] = md.distance([X[i, j], Y[i, j]])
    
    contours = plt.contourf(X, Y, Z, levels=20, cmap='YlOrRd', alpha=0.5)
    plt.colorbar(contours, label='Mahalanobis Distance')
    plt.contour(X, Y, Z, levels=10, colors='black', alpha=0.3, linewidths=0.5)
    
    # 각 시작점에서 경로 계산 및 플롯
    colors = plt.cm.viridis(np.linspace(0, 1, len(start_points)))
    
    for i, start in enumerate(start_points):
        path, distances = gradient_descent_path(md, start, learning_rate)
        plt.plot(path[:, 0], path[:, 1], color=colors[i], linewidth=2, 
                marker='o', markersize=3, label=f'Start {i+1}')
        plt.plot(start[0], start[1], '*', color=colors[i], markersize=15)
    
    plt.plot(md.mean[0], md.mean[1], 'b+', markersize=20, 
             markeredgewidth=4, label='Mean')
    
    plt.xlabel('X')
    plt.ylabel('Y')
    plt.title('Multiple Starting Points Convergence')
    plt.legend()
    plt.grid(True, alpha=0.3)
    plt.axis('equal')


def animate_gradient_descent(md, start_point, learning_rate=0.15, 
                            save_frames=False):
    """
    그래디언트 하강 과정 애니메이션 (프레임 저장)
    
    Parameters:
    -----------
    md : MahalanobisDistance
        마할라노비스 거리 객체
    start_point : array-like
        시작점
    learning_rate : float
        학습률
    save_frames : bool
        프레임 이미지 저장 여부
    """
    path, distances = gradient_descent_path(md, start_point, learning_rate)
    
    if save_frames:
        import os
        os.makedirs('frames', exist_ok=True)
    
    # 등고선 데이터 준비
    x = np.linspace(-4, 4, 100)
    y = np.linspace(-4, 4, 100)
    X, Y = np.meshgrid(x, y)
    Z = np.zeros_like(X)
    for i in range(X.shape[0]):
        for j in range(X.shape[1]):
            Z[i, j] = md.distance([X[i, j], Y[i, j]])
    
    # 각 스텝마다 플롯
    for step in range(len(path)):
        plt.figure(figsize=(10, 8))
        
        # 등고선
        plt.contourf(X, Y, Z, levels=20, cmap='YlOrRd', alpha=0.5)
        plt.contour(X, Y, Z, levels=10, colors='black', alpha=0.3, linewidths=0.5)
        
        # 지금까지의 경로
        plt.plot(path[:step+1, 0], path[:step+1, 1], 'g-', 
                linewidth=2.5, marker='o', markersize=4)
        
        # 현재 위치
        plt.plot(path[step, 0], path[step, 1], 'ro', markersize=15)
        
        # 그래디언트 벡터
        if step < len(path) - 1:
            grad = md.gradient(path[step])
            plt.arrow(path[step, 0], path[step, 1], 
                     -grad[0]*0.3, -grad[1]*0.3,
                     head_width=0.15, head_length=0.1, 
                     fc='blue', ec='blue', alpha=0.7)
        
        plt.plot(md.mean[0], md.mean[1], 'b+', markersize=20, 
                markeredgewidth=4)
        
        plt.xlabel('X')
        plt.ylabel('Y')
        plt.title(f'Gradient Descent - Step {step+1}/{len(path)}\n'
                 f'Distance: {distances[step]:.4f}')
        plt.grid(True, alpha=0.3)
        plt.axis('equal')
        plt.xlim(-4, 4)
        plt.ylim(-4, 4)
        
        if save_frames:
            plt.savefig(f'frames/frame_{step:03d}.png', dpi=100, 
                       bbox_inches='tight')
            plt.close()
        else:
            plt.pause(0.1)
            if step < len(path) - 1:
                plt.clf()
            else:
                plt.show()


# ============================================================================
# 실행
# ============================================================================

if __name__ == "__main__":
    # 메인 예제 실행
    main_example()
    
    # 추가 예제: 여러 시작점 비교
    print("\nGenerating multiple starting points comparison...")
    mean = np.array([0, 0])
    covariance = np.array([[1.5, 0.8], [0.8, 1.0]])
    md = MahalanobisDistance(mean, covariance)
    
    start_points = [
        np.array([3, 2]),
        np.array([-2, 3]),
        np.array([2, -2.5]),
        np.array([-3, -1])
    ]
    
    compare_multiple_starting_points(md, start_points)
    plt.savefig('multiple_starts.png', dpi=150, bbox_inches='tight')
    print("Saved: multiple_starts.png")
    
    plt.show()
    
    print("\n" + "=" * 60)
    print("All visualizations completed!")
    print("=" * 60)


"""
사용법:
------

1. 기본 실행:
   python mahalanobis_implementation.py

2. 커스텀 공분산 행렬로 실행:
   mean = np.array([0, 0])
   covariance = np.array([[2.0, 1.2], [1.2, 1.5]])
   md = MahalanobisDistance(mean, covariance)
   plot_optimal_paths(md, [3, 2], [-2, -1])

3. 이상치 탐지:
   data = your_data  # shape (n_samples, 2)
   outlier_detection_example(md, data, confidence=0.95)

4. 애니메이션 프레임 생성:
   animate_gradient_descent(md, [3, 2], save_frames=True)
   # ffmpeg로 동영상 생성:
   # ffmpeg -r 10 -i frames/frame_%03d.png -vcodec libx264 animation.mp4

주요 함수:
---------
- MahalanobisDistance: 거리 계산 및 그래디언트
- gradient_descent_path: 최적 경로 계산
- plot_optimal_paths: 경로 비교 시각화
- outlier_detection_example: 이상치 탐지
- plot_gradient_field_on_contour: 벡터장 시각화

필요한 라이브러리:
----------------
pip install numpy matplotlib scipy seaborn
"""
