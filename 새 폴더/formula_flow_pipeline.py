"""
문서 [최종 대통합 가설 리포트] - 유도식 1~10 통합 파이프라인
=================================================================
각 단계(step1 ~ step10)가 공통 state 딕셔너리를 이어받아 다음 단계의
입력으로 사용하는 '하나의 연산 흐름'으로 구성. 문서에 적힌 순서(1->10)를
그대로 따른다.
"""

import sympy as sp
import numpy as np


def step1_lagrangian_EM(state):
    """유도식 1: L_EM = -1/4 F_munu F^munu"""
    F = sp.symbols('F_munu')
    state['L_EM'] = -sp.Rational(1, 4) * F**2
    state['F'] = F
    print("[1] L_EM =", state['L_EM'])
    return state


def step2_lagrangian_einstein(state):
    """유도식 2: L_Einstein = R / (16 pi G)"""
    R_sym, G_sym = sp.symbols('R G', positive=True)
    state['L_Einstein'] = R_sym / (16 * sp.pi * G_sym)
    state['R_sym'], state['G_sym'] = R_sym, G_sym
    print("[2] L_Einstein =", state['L_Einstein'])
    return state


def step3_trig_cantor(state):
    """유도식 3: L_Trig-Cantor = kappa*sin(Ax)cos(Bx)*R_Cantor + 탄젠트 폭발 항"""
    A, B, x, kappa, theta, ktotal = sp.symbols('A B x kappa theta k_total', real=True)
    R_cantor = sp.Symbol('R_Cantor')

    L_trig = kappa * sp.sin(A * x) * sp.cos(B * x) * R_cantor
    # 합차공식 전개 (앞 단계 라그랑지안에 이어붙일 전개 형태)
    expanded = kappa * sp.Rational(1, 2) * (sp.sin((A + B) * x) + sp.sin((A - B) * x)) * R_cantor
    identity_check = sp.simplify(sp.expand_trig(L_trig - expanded))

    grad_trig = sp.Symbol('F_TrigCantor') * sp.tan(ktotal * x)

    state.update(dict(
        L_trig=L_trig, L_trig_expanded=expanded,
        identity_check=identity_check,
        grad_trig=grad_trig, ktotal=ktotal, x=x, theta=theta, kappa=kappa,
    ))
    print("[3] L_Trig-Cantor =", L_trig)
    print("    합차공식 전개 일치 확인 (0이어야 함):", identity_check)
    print("    국소 위상 기울기 ∇L_Trig-Cantor =", grad_trig, " (θ→π/2 에서 tan→±∞)")
    return state


def step4_mhd_energy(state):
    """유도식 4: 3D MHD 운동량 방정식 + 에너지 상한 부등식.
    이전 단계의 grad_trig(tan 발산항)을 압력항으로 그대로 이어받는다."""
    rho, p_pres, t, x_ = sp.symbols('rho p t x', real=True)
    u_vec = sp.Function('u')(x_, t)
    Su = sp.Function('S_u')(x_, t)
    C_EL, k_B = sp.symbols('C_EL k_B', positive=True)

    # step3의 tan 폭주항을 그대로 source term으로 연결
    source_term = C_EL * sp.exp(Su / k_B) * sp.diff(state['grad_trig'], state['x'])

    momentum_eq = sp.Eq(
        rho * (sp.diff(u_vec, t) + u_vec * sp.diff(u_vec, x_)),
        -sp.diff(p_pres, x_) + sp.Symbol('(curl_B_x_B)') + source_term
    )
    print("[4] 운동량 방정식 (step3의 tan 발산항을 source term으로 연결):")
    sp.pprint(momentum_eq)

    # 에너지 상한 부등식의 수치 데모: u = sin(kx) e^{-νk²t} 로 토이 검증
    k_, nu_ = 1.5, 0.3
    def grad_u_sq(x_val, t_val):
        return (k_ * np.cos(k_ * x_val) * np.exp(-nu_ * k_**2 * t_val)) ** 2
    xs = np.linspace(0, 2 * np.pi, 400)
    ts = np.linspace(0.01, 5, 400)
    X, T = np.meshgrid(xs, ts)
    energy_integral = np.trapezoid(np.trapezoid(grad_u_sq(X, T), xs, axis=1), ts)
    print(f"    ∫∫|∂u/∂x|² dx dt (수치) = {energy_integral:.4f}  (유한 -> 부등식 형태 만족하는 예시)")

    state.update(dict(momentum_eq=momentum_eq, C_EL=C_EL, k_B=k_B, energy_integral=energy_integral))
    return state


def step5_burgers(state):
    """유도식 5: 버거스 방정식 + 콜-호프 치환"""
    xi, t, nu = sp.symbols('xi t nu', positive=True, real=True)
    phi = sp.Function('phi')(xi, t)
    u = sp.Function('u')(xi, t)

    u_sub = -2 * nu * sp.diff(phi, xi) / phi
    burgers_lhs = sp.diff(u, t) + u * sp.diff(u, xi)
    burgers_rhs = nu * sp.diff(u, xi, 2)
    reduced = sp.simplify((burgers_lhs - burgers_rhs).subs(u, u_sub))

    print("[5] 콜-호프 치환 u=-2ν(∂φ/∂ξ)/φ 대입 후 버거스 방정식 (정리하면 선형 열방정식으로 환원):")
    print("   ", reduced)

    state.update(dict(xi=xi, t_burgers=t, nu=nu, phi=phi, u_sub=u_sub))
    return state


def step6_cole_hopf_solution(state):
    """유도식 6: 선형화된 열방정식의 해 φ(ξ,t).
    step5에서 만든 nu, xi, phi를 그대로 이어받아 해를 검증한다."""
    nu_val = 0.5
    C_EL_val = 1.0

    def phi_func(x, tt):
        return C_EL_val / np.sqrt(4 * np.pi * nu_val * tt) * np.exp(-x**2 / (4 * nu_val * tt)) + C_EL_val

    x0, t0, dt, dx = 0.7, 2.0, 1e-4, 1e-4
    dphidt = (phi_func(x0, t0 + dt) - phi_func(x0, t0 - dt)) / (2 * dt)
    d2phidx2 = (phi_func(x0 + dx, t0) - 2 * phi_func(x0, t0) + phi_func(x0 - dx, t0)) / dx**2

    print("[6] φ(ξ,t) = C_EL/√(4πνt) exp(-ξ²/4νt) + C_EL 가 열방정식을 만족하는지 수치 검증:")
    print(f"    ∂φ/∂t = {dphidt:.6f},  ν·∂²φ/∂ξ² = {nu_val * d2phidx2:.6f}  (거의 같아야 정상)")

    # step5의 u_sub에 이 해를 대입했을 때의 최종 u(ξ,t) 값을 같은 점에서 추출 (흐름 연결)
    u_val = -2 * nu_val * (phi_func(x0 + dx, t0) - phi_func(x0 - dx, t0)) / (2 * dx) / phi_func(x0, t0)
    print(f"    해당 점에서의 속도장 u(ξ,t) = -2ν(∂φ/∂ξ)/φ = {u_val:.6f}")

    state.update(dict(nu_val=nu_val, C_EL_val=C_EL_val, phi_func=phi_func, u_val=u_val))
    return state


def step7_hyperbolic_metric(state):
    """유도식 7: 쌍곡 메트릭과 리치 스칼라 곡률"""
    xi_sym, x2_sym = sp.symbols('xi x2', positive=True)
    g = sp.diag(-1 / xi_sym**2, 1 / xi_sym**2)
    coords = [xi_sym, x2_sym]

    def ricci_scalar_2d(metric, coords):
        n = len(coords)
        ginv = metric.inv()
        Gamma = [[[0] * n for _ in range(n)] for _ in range(n)]
        for a in range(n):
            for b in range(n):
                for c in range(n):
                    s = 0
                    for d in range(n):
                        s += ginv[a, d] * (
                            sp.diff(metric[d, b], coords[c])
                            + sp.diff(metric[d, c], coords[b])
                            - sp.diff(metric[b, c], coords[d])
                        )
                    Gamma[a][b][c] = sp.simplify(s / 2)
        Ricci = sp.zeros(n, n)
        for b in range(n):
            for c in range(n):
                s = 0
                for a in range(n):
                    s += sp.diff(Gamma[a][b][c], coords[a])
                    s -= sp.diff(Gamma[a][b][a], coords[c])
                    s += sum(Gamma[a][a][e] * Gamma[e][b][c] for e in range(n))
                    s -= sum(Gamma[a][c][e] * Gamma[e][b][a] for e in range(n))
                Ricci[b, c] = sp.simplify(s)
        return sp.simplify(sum(ginv[i, j] * Ricci[i, j] for i in range(n) for j in range(n))), Gamma

    R_scalar, Gamma = ricci_scalar_2d(g, coords)
    print("[7] 쌍곡 메트릭 diag(-1,1)/ξ² 의 리치 스칼라 곡률 R =", R_scalar)

    state.update(dict(xi_sym=xi_sym, x2_sym=x2_sym, g=g, coords=coords, R_scalar=R_scalar, Gamma=Gamma))
    return state


def step8_curvature_vector(state):
    """유도식 8: 쌍곡 곡률 가속도 벡터 H_mu.
    step7에서 얻은 R_scalar, xi_sym을 그대로 이어받아 사용."""
    xi_sym = state['xi_sym']
    H_mu_expr = -1 / xi_sym**2 * sp.diff(xi_sym, xi_sym)
    H_mu_value = sp.simplify(H_mu_expr)

    print("[8] H_μ = -(1/ξ²)∇_μξ  (step7의 곡률 좌표 ξ를 그대로 사용) =", H_mu_value)
    sample_vals = {v: H_mu_value.subs(xi_sym, v) for v in (1, 2, 5)}
    print("    ξ = 1, 2, 5 에서:", sample_vals)

    state.update(dict(H_mu_value=H_mu_value, sample_vals=sample_vals))
    return state


def step9_ode_slope(state):
    """유도식 9: du/dξ = C_EL*K_dim/cosθ.
    step6의 C_EL_val을 그대로 이어받아 수치까지 계산."""
    theta, Kdim = sp.symbols('theta K_dim', real=True)
    C_EL_sym = sp.Symbol('C_EL')
    du_dxi_expr = C_EL_sym * Kdim / sp.cos(theta)
    limit_val = sp.limit(du_dxi_expr, theta, 0)

    # step6에서 나온 수치 C_EL_val을 대입해 실제 값까지 흐름을 이어간다
    Kdim_val = 2.0
    numeric_val = limit_val.subs({C_EL_sym: state['C_EL_val'], Kdim: Kdim_val})

    print("[9] du/dξ =", du_dxi_expr, " -> θ→0 극한 =", limit_val)
    print(f"    step6의 C_EL={state['C_EL_val']}, K_dim={Kdim_val} 대입 시 du/dξ = {numeric_val}")

    state.update(dict(du_dxi_limit=limit_val, du_dxi_numeric=numeric_val))
    return state


def step10_schrodinger_expectation(state):
    """유도식 10: 슈뢰딩거 기댓값 Γ(ξ) = <psi|H|psi>"""
    x_sym, k_n = sp.symbols('x k', real=True, positive=True)
    hbar_sym, m_sym = sp.symbols('hbar m', positive=True)
    psi = sp.sqrt(2) * sp.sin(k_n * sp.pi * x_sym)
    H_psi = -hbar_sym**2 / (2 * m_sym) * sp.diff(psi, x_sym, 2)
    expectation = sp.simplify(sp.integrate(sp.conjugate(psi) * H_psi, (x_sym, 0, 1)))

    print("[10] Γ(ξ) = <ψ|H|ψ> (예시 ψ=√2 sin(kπx)) =", expectation)

    state.update(dict(expectation=expectation))
    return state


def run_pipeline():
    state = {}
    pipeline = [
        step1_lagrangian_EM,
        step2_lagrangian_einstein,
        step3_trig_cantor,
        step4_mhd_energy,
        step5_burgers,
        step6_cole_hopf_solution,
        step7_hyperbolic_metric,
        step8_curvature_vector,
        step9_ode_slope,
        step10_schrodinger_expectation,
    ]
    for i, step in enumerate(pipeline, start=1):
        print("\n" + "=" * 70)
        state = step(state)
    print("\n" + "=" * 70)
    print("파이프라인 종료. 최종 state 키 목록:")
    print(sorted(state.keys()))
    return state


if __name__ == "__main__":
    final_state = run_pipeline()
