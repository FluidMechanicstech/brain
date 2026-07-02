"""
visualize_physics_engine.py
=================================================================
physics_engine.py 의 두 시나리오(정적/동적)를 그대로 실행하면서
내부 상태(궤적, 배경 포텐셜, 속도장 시계열 등)를 추가로 기록해
matplotlib 정적 그림 + 애니메이션(GIF)으로 시각화한다.

physics_engine.py 의 함수/상수를 import 해서 재사용하므로,
두 파일은 같은 디렉터리에 있어야 한다.

생성 파일:
  - static_scenario.png   : 평형 구성 + 배경장 등고선 + 에너지 수렴 곡선
  - dynamic_scenario.png  : 초기/최종/해석해 속도장, 에너지 시간 변화, MHD 소스항
  - dynamic_scenario.gif  : u(x,t) 시간 전개 애니메이션 (수치해 vs 콜-호프 해석해)
"""

import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.animation import FuncAnimation, PillowWriter

from physics_engine import (
    FieldConstants,
    trig_cantor_potential,
    hyperbolic_confinement_potential,
    total_static_energy,
    numerical_gradient,
    cole_hopf_velocity,
    mhd_source_term,
)


# ---------------------------------------------------------------------------
# 정적 시나리오 시각화
# ---------------------------------------------------------------------------

def visualize_static_scenario(n_particles=4, steps=4000, lr=0.01, seed=0,
                               save_path="static_scenario.png"):
    """run_static_scenario()와 동일한 경사하강 루프를 돌리되,
    중간 위치/에너지를 모두 기록해 궤적과 수렴 곡선을 그린다."""
    rng = np.random.default_rng(seed)
    c = FieldConstants()
    charges = rng.uniform(0.2, 1.0, size=n_particles) * rng.choice([-1, 1], size=n_particles)
    positions = rng.uniform(-2, 2, size=(n_particles, 2))
    flat = positions.flatten()

    def energy_fn(flat_vec):
        pos = flat_vec.reshape(n_particles, 2)
        return total_static_energy(pos, charges, c)

    snap_every = max(1, steps // 150)
    traj = [flat.reshape(n_particles, 2).copy()]
    energy_history = [(0, energy_fn(flat))]

    for step in range(steps):
        grad = numerical_gradient(energy_fn, flat)
        flat = flat - lr * grad
        if step % snap_every == 0 or step == steps - 1:
            traj.append(flat.reshape(n_particles, 2).copy())
            energy_history.append((step + 1, energy_fn(flat)))

    final_positions = flat.reshape(n_particles, 2)
    traj_arr = np.array(traj)  # (n_snapshots, n_particles, 2)
    steps_axis = [s for s, _ in energy_history]
    energy_axis = [e for _, e in energy_history]

    def draw_field_panel(ax, span, title):
        """배경장(트리그-칸토어 + 쌍곡 구속) 등고선 위에 입자 궤적/최종 위치를 그린다."""
        grid_n = 220
        xv = np.linspace(-span, span, grid_n)
        yv = np.linspace(-span, span, grid_n)
        XX, YY = np.meshgrid(xv, yv)
        bg = trig_cantor_potential(XX, YY, c) + hyperbolic_confinement_potential(np.hypot(XX, YY), c)
        im = ax.contourf(XX, YY, bg, levels=40, cmap="RdBu_r")
        for i in range(n_particles):
            ax.plot(traj_arr[:, i, 0], traj_arr[:, i, 1], "-", color="black", alpha=0.4, lw=1)
            ax.plot(traj_arr[0, i, 0], traj_arr[0, i, 1], "x", color="black", ms=6)
        colors = ["#d62728" if q > 0 else "#1f77b4" for q in charges]
        sizes = 120 + 260 * np.abs(charges) / np.max(np.abs(charges))
        ax.scatter(final_positions[:, 0], final_positions[:, 1], c=colors, s=sizes,
                   edgecolors="black", linewidths=1.2, zorder=5)
        # 라벨이 서로 겹치지 않도록 x좌표 순서대로 위/아래 오프셋을 번갈아 적용
        order = np.argsort(final_positions[:, 0])
        for rank, i in enumerate(order):
            x, y = final_positions[i]
            if not (-span <= x <= span and -span <= y <= span):
                continue
            dy = 14 if rank % 2 == 0 else -18
            ax.annotate(f"q{i}={charges[i]:+.2f}", (x, y), textcoords="offset points",
                        xytext=(0, dy), ha="center", fontsize=8, fontweight="bold")
        ax.set_xlim(-span, span); ax.set_ylim(-span, span)
        ax.set_title(title)
        ax.set_xlabel("x"); ax.set_ylabel("y")
        ax.set_aspect("equal")
        return im

    fig, axes = plt.subplots(1, 3, figsize=(18, 5.5))

    # --- 왼쪽: 전체 스케일 (튀어나간 입자까지 포함) ---
    full_span = max(3.0, np.abs(traj_arr).max() * 1.15)
    im0 = draw_field_panel(axes[0], full_span, "Full view (start=x, final=●)")
    fig.colorbar(im0, ax=axes[0], fraction=0.046, pad=0.04)

    # --- 중앙: 원점에 가장 가까운 입자들(최소 2개, 최대 절반)로 확대 ---
    dists_sorted_idx = np.argsort(np.linalg.norm(final_positions, axis=1))
    cut = max(2, n_particles // 2)
    cluster_positions = final_positions[dists_sorted_idx[:cut]]
    zoom_span = max(2.0, np.abs(cluster_positions).max() * 1.8)
    im1 = draw_field_panel(axes[1], zoom_span, f"Zoom on nearest cluster (span=\u00b1{zoom_span:.1f})")
    fig.colorbar(im1, ax=axes[1], fraction=0.046, pad=0.04)

    # --- 오른쪽: 에너지 수렴 곡선 ---
    ax2 = axes[2]
    ax2.plot(steps_axis, energy_axis, "-", color="#2ca02c", lw=1.5)
    ax2.set_xlabel("gradient descent step")
    ax2.set_ylabel("total energy")
    ax2.set_title("Energy minimization convergence")
    ax2.grid(alpha=0.3)

    fig.suptitle("Static scenario: EM pair + trig-cantor field + hyperbolic confinement", y=1.03)
    fig.tight_layout()
    fig.savefig(save_path, dpi=150, bbox_inches="tight")
    plt.close(fig)

    # 같은 부호 전하가 약한 -1/xi 구속을 뚫고 멀리 퍼지는지 콘솔에도 보고
    dists = np.linalg.norm(final_positions, axis=1)
    print(f"[static] 원점으로부터의 최종 거리: {np.round(dists, 3)}")

    final_grad = numerical_gradient(energy_fn, flat)
    print(f"[static] saved -> {save_path}")
    print(f"[static] final energy = {energy_axis[-1]:.6f}, "
          f"residual force norm = {np.linalg.norm(final_grad):.6f}")

    return dict(final_positions=final_positions, charges=charges,
                energy_history=energy_axis, traj=traj_arr)


# ---------------------------------------------------------------------------
# 동적 시나리오 시각화
# ---------------------------------------------------------------------------

def visualize_dynamic_scenario(n_x=200, x_max=6.0, n_steps=300, dt=2e-3, t0=0.5,
                                save_png="dynamic_scenario.png",
                                save_gif="dynamic_scenario.gif",
                                n_frames=80):
    """run_dynamic_scenario()와 동일한 시간 적분을 돌리되,
    u(x,t) 스냅샷을 모아서 GIF 애니메이션을 만든다."""
    c = FieldConstants()
    xs = np.linspace(-x_max, x_max, n_x)
    dx_grid = xs[1] - xs[0]

    u = cole_hopf_velocity(xs, t0, c)
    snap_every = max(1, n_steps // n_frames)

    u_snapshots = [u.copy()]
    t_snapshots = [t0]
    energies = []

    t = t0
    for step in range(n_steps):
        u_x = np.gradient(u, dx_grid)
        u_xx = np.gradient(u_x, dx_grid)
        source = mhd_source_term(xs, c)

        u_new = u + dt * (-u * u_x + c.nu * u_xx + source)
        u_new[0], u_new[-1] = u_new[1], u_new[-2]
        u = u_new
        t += dt

        energies.append(float(np.trapezoid(u ** 2, xs)))
        if step % snap_every == 0 or step == n_steps - 1:
            u_snapshots.append(u.copy())
            t_snapshots.append(t)

    analytic_final = cole_hopf_velocity(xs, t, c)
    rel_err = float(np.linalg.norm(u - analytic_final) / (np.linalg.norm(analytic_final) + 1e-9))

    # --- 정적 요약 그림: 초기/최종/해석해, 에너지 곡선, MHD 소스항 ---
    fig, axes = plt.subplots(1, 3, figsize=(17, 5))

    ax0 = axes[0]
    ax0.plot(xs, u_snapshots[0], "--", color="gray", label=f"initial (t0={t0})")
    ax0.plot(xs, u, "-", color="crimson", label=f"numerical (t={t:.3f})")
    ax0.plot(xs, analytic_final, ":", color="navy", lw=2, label="cole-hopf analytic")
    ax0.set_xlabel("x"); ax0.set_ylabel("u(x,t)")
    ax0.set_title("Burgers + MHD source velocity field")
    ax0.legend(fontsize=8); ax0.grid(alpha=0.3)

    ax1 = axes[1]
    t_axis = t0 + dt * np.arange(1, len(energies) + 1)
    ax1.plot(t_axis, energies, color="#2ca02c")
    ax1.set_xlabel("t"); ax1.set_ylabel(r"$\int u^2\,dx$")
    ax1.set_title("Energy time evolution")
    ax1.grid(alpha=0.3)

    ax2 = axes[2]
    source_vals = mhd_source_term(xs, c)
    ax2.plot(xs, source_vals, color="purple")
    ax2.set_xlabel("x"); ax2.set_ylabel("source(x)")
    ax2.set_title("MHD / tan source term (capped)")
    ax2.grid(alpha=0.3)

    fig.suptitle(f"Dynamic scenario summary  (final relative error vs analytic = {rel_err:.4f})", y=1.03)
    fig.tight_layout()
    fig.savefig(save_png, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"[dynamic] saved -> {save_png}")

    # --- 애니메이션: u(x,t) 수치해 vs 해석해 ---
    fig2, ax = plt.subplots(figsize=(8, 5))
    y_min = min(np.min(s) for s in u_snapshots)
    y_max = max(np.max(s) for s in u_snapshots)
    pad = 0.15 * (y_max - y_min + 1e-6)

    line_num, = ax.plot(xs, u_snapshots[0], color="crimson", lw=2, label="numerical (Burgers+MHD)")
    line_ana, = ax.plot(xs, cole_hopf_velocity(xs, t_snapshots[0], c), color="navy", ls=":", lw=2,
                         label="cole-hopf analytic")
    ax.set_xlim(xs.min(), xs.max())
    ax.set_ylim(y_min - pad, y_max + pad)
    ax.set_xlabel("x"); ax.set_ylabel("u(x,t)")
    ax.legend(loc="upper right", fontsize=9)
    ax.grid(alpha=0.3)
    title = ax.set_title("")

    def update(frame):
        line_num.set_ydata(u_snapshots[frame])
        line_ana.set_ydata(cole_hopf_velocity(xs, t_snapshots[frame], c))
        title.set_text(f"t = {t_snapshots[frame]:.4f}")
        return line_num, line_ana, title

    anim = FuncAnimation(fig2, update, frames=len(u_snapshots), interval=120, blit=False)
    anim.save(save_gif, writer=PillowWriter(fps=10))
    plt.close(fig2)
    print(f"[dynamic] saved -> {save_gif}")

    return dict(t_final=t, relative_error=rel_err, energies=np.array(energies),
                u_snapshots=u_snapshots, t_snapshots=t_snapshots)


if __name__ == "__main__":
    print("정적 시나리오 시각화 생성 중...")
    static_result = visualize_static_scenario()
    print()
    print("동적 시나리오 시각화 생성 중...")
    dynamic_result = visualize_dynamic_scenario()
