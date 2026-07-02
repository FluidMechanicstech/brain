"""
물리엔진 대량 시각화 생산기 - 다양성 강화 버전
"""

import numpy as np
import os
from visualize_physics_engine import visualize_static_scenario, visualize_dynamic_scenario

def mass_produce_viz(num_sets=12):
    print("🚀 물리엔진 대량 시각화 생산 시작 (다양성 최대화)\n")
    
    output_dir = "my_physics_visualizations"
    os.makedirs(output_dir, exist_ok=True)
    
    for i in range(num_sets):
        # 다양한 파라미터 조합
        n_particles = np.random.choice([4, 5, 6, 7, 8, 10, 12, 15])
        lr = round(np.random.uniform(0.005, 0.035), 4)
        seed = np.random.randint(10, 9999)
        tag = np.random.choice(["stable", "chaotic", "cluster", "spread", "balance", "strong", "weak"])
        
        name = f"{tag}_n{n_particles}_lr{lr}_s{seed}"
        
        print(f"[{i+1:2d}/{num_sets}] {name} 생성 중...")
        
        # 정적 시각화 (평형)
        visualize_static_scenario(
            n_particles=n_particles,
            steps=1800 + n_particles*80,
            lr=lr,
            seed=seed,
            save_path=f"{output_dir}/{name}_static.png"
        )
        
        # 동적 시각화 (GIF)
        visualize_dynamic_scenario(
            n_x=160,
            x_max=6.5,
            n_steps=180 + n_particles*8,
            dt=round(np.random.uniform(0.0012, 0.0035), 4),
            save_png=f"{output_dir}/{name}_dynamic.png",
            save_gif=f"{output_dir}/{name}_dynamic.gif",
            n_frames=50
        )
        
        print(f"   ✓ 완료: {name}\n")
    
    print(f"🎉 생산 완료! {num_sets}세트 ({num_sets*3}개 파일)")
    print(f"   폴더 위치: {output_dir}/")

if __name__ == "__main__":
    mass_produce_viz(num_sets=12)   # 숫자 바꾸면 더 많이 생성됨 (15~20 추천)