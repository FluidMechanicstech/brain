"""
physics_engine.py
=================================================================
formula_flow_pipeline.py 의 유도식 1~10을 '재료'로 삼아 만든 토이 물리 엔진.

- 정적(static) 시나리오 : run_static_scenario()
    시간(t) 축이 없는 힘의 평형(equilibrium) 구성 탐색.
    유도식 1(EM), 3(트리그-칸토어 배경장), 7·8(쌍곡 곡률 구속 포텐셜)을 사용.

- 동적(dynamic) 시나리오 : run_dynamic_scenario()
    시간에 따라 속도장 u(x,t)를 PDE로 전개.
    유도식 3·4(MHD 소스항), 5·6(버거스 + 콜-호프 해석해)을 사용해 시간 적분하고,
    유도식 10(슈뢰딩거 기댓값)을 보조 에너지 진단값으로 곁들인다.

주의: 전자기학·일반상대성·MHD·버거스 방정식·쌍곡기하·양자역학은 서로 다른
이론 체계이며, 원본 문서처럼 한 식의 결과를 다른 식에 그대로 대입한다고
해서 물리적으로 타당한 통합이 되는 것은 아닙니다. 이 스크립트는 그 수식들의
'형태'를 시뮬레이션 구성 요소로 차용한 교육·창작용 토이 엔진입니다.
"""

import numpy as np


# ---------------------------------------------------------------------------
# 공통 상수 (유도식 1,3,4,5,6,7,8에서 등장하는 기호들을 한 곳에 모음)
# ---------------------------------------------------------------------------

class FieldConstants:
    def __init__(self):
        self.kappa = 0.6        # 유도식 3: 트리그-칸토어 결합상수
        self.A = 1.3            # 유도식 3
        self.B = 0.7            # 유도식 3
        self.R_cantor = 1.0     # 유도식 3: 배경 곡률 스칼라
        self.k_total = 0.05     # 유도식 3: tan 발산항의 위상 계수 (작게 잡아 특이점 회피)
        self.C_EL = 1.0         # 유도식 4,6,9
        self.k_B = 1.0          # 유도식 4
        self.nu = 0.5           # 유도식 5,6: 점성/확산 계수


def trig_cantor_potential(x, y, c: FieldConstants):
    """유도식 3: kappa*sin(Ax)cos(By)*R_Cantor 를 2D 배경 포텐셜로 사용."""
    return c.kappa * np.sin(c.A * x) * np.cos(c.B * y) * c.R_cantor


def hyperbolic_confinement_potential(xi, c: FieldConstants, eps=1e-3):
    """유도식 7,8: 쌍곡 메트릭 diag(-1,1)/xi^2 의 곡률 가속도
    H_mu = -1/xi^2 를 적분해 얻은 원점 방향 구속 포텐셜 V(xi) = -1/xi."""
    xi = np.maximum(xi, eps)
    return -1.0 / xi


def em_pair_potential(r, q1, q2, eps=1e-3):
    """유도식 1: L_EM = -1/4 F^2 에서 차용한 단순 쿨롱형 쌍 상호작용."""
    r = max(r, eps)
    return q1 * q2 / r


# ---------------------------------------------------------------------------
# 정적(static) 시나리오 — 시간 축 없는 힘의 평형 탐색
# ---------------------------------------------------------------------------

def total_static_energy(positions, charges, c: FieldConstants):
    """N개 입자의 총 에너지 = EM 쌍 상호작용 + 트리그-칸토어 배경장 + 쌍곡 구속."""
    n = len(positions)
    E = 0.0
    for i in range(n):
        x, y = positions[i]
        r_origin = np.hypot(x, y)
        E += hyperbolic_confinement_potential(r_origin, c)
        E += trig_cantor_potential(x, y, c)
        for j in range(i + 1, n):
            xj, yj = positions[j]
            r = np.hypot(x - xj, y - yj)
            E += em_pair_potential(r, charges[i], charges[j])
    return E


def numerical_gradient(f, vec, h=1e-5):
    grad = np.zeros_like(vec)
    for i in range(len(vec)):
        vp = vec.copy(); vp[i] += h
        vm = vec.copy(); vm[i] -= h
        grad[i] = (f(vp) - f(vm)) / (2 * h)
    return grad


def run_static_scenario(n_particles=4, steps=4000, lr=0.01, seed=0, verbose=True):
    """경사하강법으로 총 에너지를 최소화하는 평형 구성을 탐색한다.
    -> 시간(t) 축이 없는 '정적' 시나리오."""
    rng = np.random.default_rng(seed)
    c = FieldConstants()
    charges = rng.uniform(0.2, 1.0, size=n_particles) * rng.choice([-1, 1], size=n_particles)
    positions = rng.uniform(-2, 2, size=(n_particles, 2))
    flat = positions.flatten()

    def energy_fn(flat_vec):
        pos = flat_vec.reshape(n_particles, 2)
        return total_static_energy(pos, charges, c)

    history = []
    for step in range(steps):
        grad = numerical_gradient(energy_fn, flat)
        flat = flat - lr * grad
        if step % max(1, steps // 10) == 0 or step == steps - 1:
            history.append((step, energy_fn(flat)))

    final_positions = flat.reshape(n_particles, 2)
    final_grad = numerical_gradient(energy_fn, flat)
    final_energy = energy_fn(flat)
    residual_force = float(np.linalg.norm(final_grad))

    if verbose:
        print("=" * 70)
        print("[정적 시나리오] 힘의 평형 구성 탐색")
        print("=" * 70)
        print(f"입자 수: {n_particles}, 전하: {np.round(charges, 3)}")
        for step, e in history:
            print(f"  step {step:5d}   E = {e:.6f}")
        print(f"최종 위치:\n{np.round(final_positions, 4)}")
        print(f"최종 에너지: {final_energy:.6f}")
        print(f"잔류 기울기 노름(힘의 불균형, 0에 가까울수록 평형): {residual_force:.6f}")

    return dict(positions=final_positions, charges=charges, energy=final_energy,
                residual_force=residual_force)


# ---------------------------------------------------------------------------
# 동적(dynamic) 시나리오 — 시간에 따른 속도장 전개
# ---------------------------------------------------------------------------

def cole_hopf_phi(x, t, c: FieldConstants):
    """유도식 6: phi(x,t) = C_EL/sqrt(4*pi*nu*t) * exp(-x^2/(4*nu*t)) + C_EL."""
    t = max(t, 1e-4)
    return c.C_EL / np.sqrt(4 * np.pi * c.nu * t) * np.exp(-x**2 / (4 * c.nu * t)) + c.C_EL


def cole_hopf_velocity(x, t, c: FieldConstants, dx=1e-4):
    """유도식 5,6: u(x,t) = -2*nu*(d phi/dx)/phi (콜-호프 치환의 역산)."""
    phi_p = cole_hopf_phi(x + dx, t, c)
    phi_m = cole_hopf_phi(x - dx, t, c)
    phi_0 = cole_hopf_phi(x, t, c)
    dphidx = (phi_p - phi_m) / (2 * dx)
    return -2 * c.nu * dphidx / phi_0


def mhd_source_term(x, c: FieldConstants, cap=5.0):
    """유도식 3,4: tan(k_total*x) 발산항을 MHD 운동량 방정식의 압력원으로 사용.
    d/dx[tan(kx)] = k*sec^2(kx) 이며, 발산을 그대로 두면 적분이 불가능하므로
    cap으로 절단(정규화)한다 — 원본 문서가 명시한 θ→π/2 특이점에 대한 처리."""
    raw = c.k_total * c.kappa / np.cos(c.k_total * x) ** 2
    return np.clip(raw, -cap, cap) * c.C_EL


def schrodinger_energy_diagnostic(k_n=1, hbar=1.0, m=1.0):
    """유도식 10: Γ = <psi|H|psi>, psi = sqrt(2) sin(k*pi*x), 0<=x<=1.
    해석적으로 (k*pi*hbar)^2/(2m) 인 무한 우물 에너지.
    동적 시나리오 안에서는 별 의미 없는 보조 에너지 스케일 진단값으로만 사용."""
    return (k_n * np.pi * hbar) ** 2 / (2 * m)


def run_dynamic_scenario(n_x=200, x_max=6.0, n_steps=300, dt=2e-3, t0=0.5, verbose=True):
    """1D 버거스+MHD 소스항 결합 PDE를 명시적 유한차분으로 시간 전개.
    초기조건은 콜-호프 해석해(유도식6)에서 가져온다."""
    c = FieldConstants()
    xs = np.linspace(-x_max, x_max, n_x)
    dx_grid = xs[1] - xs[0]

    u = cole_hopf_velocity(xs, t0, c)
    energies = []
    snapshots = []

    t = t0
    for step in range(n_steps):
        u_x = np.gradient(u, dx_grid)
        u_xx = np.gradient(u_x, dx_grid)
        source = mhd_source_term(xs, c)

        u_new = u + dt * (-u * u_x + c.nu * u_xx + source)
        u_new[0], u_new[-1] = u_new[1], u_new[-2]  # 단순 경계조건
        u = u_new
        t += dt

        energy = float(np.trapezoid(u ** 2, xs))
        energies.append(energy)
        if step % max(1, n_steps // 10) == 0 or step == n_steps - 1:
            snapshots.append((round(t, 4), energy))

    analytic_u_final = cole_hopf_velocity(xs, t, c)
    rel_err = float(np.linalg.norm(u - analytic_u_final) / (np.linalg.norm(analytic_u_final) + 1e-9))
    quantum_diag = schrodinger_energy_diagnostic()

    if verbose:
        print("=" * 70)
        print("[동적 시나리오] 버거스+MHD 소스항 결합 속도장 시간 전개")
        print("=" * 70)
        print(f"격자점 수: {n_x}, dt={dt}, 초기시각 t0={t0}")
        for t_val, e in snapshots:
            print(f"  t = {t_val:7.4f}   ∫u² dx = {e:.6f}")
        print(f"최종 시각 t={t:.4f} 에서 수치해 vs 콜-호프 해석해 상대오차: {rel_err:.6f}")
        print(f"보조 진단(유도식10, 슈뢰딩거 무한우물 k=1 에너지 스케일): {quantum_diag:.6f}")

    return dict(x=xs, u_final=u, energies=np.array(energies), t_final=t,
                relative_error=rel_err, quantum_diagnostic=quantum_diag)


if __name__ == "__main__":
    run_static_scenario()
    print()
    run_dynamic_scenario()
