#!/bin/bash
for file in Examples2/Sample_paper/sfone/*
do
    python3 Build_SCDG.py $file --eval_time --symb_loop=4 --conc_loop=1024 --simul_state=10 --method=CBFS --max_step=50000  --max_deadend=25000 --exp_dir=output/save_CBFS_syscall/
    rm outputs/*
done

7z a Result/sfone_CBFS.7z Result/save_CBFS_syscall/
rm Result/save_CBFS_syscall/*

for file in Examples2/Sample_paper/shiz/*
do
    python3 Build_SCDG.py $file --eval_time --symb_loop=4 --conc_loop=1024 --simul_state=10 --method=CBFS --max_step=50000  --max_deadend=25000 --exp_dir=Result/save_CBFS_syscall/
    rm outputs/*
done

7z a Result/shiz_CBFS.7z Result/save_CBFS_syscall/
rm Result/save_CBFS_syscall/*

for file in Examples2/Sample_paper/Sodinokibi/*
do
    python3 Build_SCDG.py $file --eval_time --symb_loop=4 --conc_loop=1024 --simul_state=10 --method=CBFS --max_step=50000  --max_deadend=25000 --exp_dir=Result/save_CBFS_syscall/
    rm outputs/*
done

7z a Result/Sodinokibi_CBFS.7z Result/save_CBFS_syscall/
rm Result/save_CBFS_syscall/*

for file in Examples2/Sample_paper/sillyp2p/*
do
    python3 Build_SCDG.py $file --eval_time --symb_loop=4 --conc_loop=1024 --simul_state=10 --method=CBFS --max_step=50000  --max_deadend=25000 --exp_dir=Result/save_CBFS_syscall/
    rm outputs/*
done

7z a Result/sillyp2p_CBFS.7z Result/save_CBFS_syscall/
rm Result/save_CBFS_syscall/*

exit 0

for file in Examples/Sample_paper/bancteian/*
do
    python3 Build_SCDG.py $file --eval_time --symb_loop=4 --conc_loop=1024 --simul_state=10 --method=CBFS --max_step=50000  --max_deadend=25000 --exp_dir=Result/save_CBFS_syscall/
    rm outputs/*
done

7z a Result/bancteian_CBFS.7z Result/save_CBFS_syscall/
rm Result/save_CBFS_syscall/*

for file in Examples2/Sample_paper/simbot/*
do
    python3 Build_SCDG.py $file --eval_time --symb_loop=4 --conc_loop=1024 --simul_state=10 --method=CBFS --max_step=50000  --max_deadend=25000 --exp_dir=Result/save_CBFS_syscall/
    rm outputs/*
done

7z a Result/simbot_CBFS.7z Result/save_CBFS_syscall/
rm Result/save_CBFS_syscall/*

for file in Examples2/Sample_paper/stormattack/*
do
    python3 Build_SCDG.py $file --eval_time --symb_loop=4 --conc_loop=1024 --simul_state=10 --method=CBFS --max_step=50000  --max_deadend=25000 --exp_dir=Result/save_CBFS_syscall/
    rm outputs/*
done

7z a Result/stormattack_CBFS.7z Result/save_CBFS_syscall/
rm Result/save_CBFS_syscall/*

for file in Examples2/Sample_paper/sytro/*
do
    python3 Build_SCDG.py $file --eval_time --symb_loop=4 --conc_loop=1024 --simul_state=10 --method=CBFS --max_step=50000  --max_deadend=25000 --exp_dir=Result/save_CBFS_syscall/
    rm outputs/*
done

7z a Result/sytro_CBFS.7z Result/save_CBFS_syscall/
rm Result/save_CBFS_syscall/*


for file in Examples2/Sample_paper/wabot/*
do
    python3 Build_SCDG.py $file --eval_time --symb_loop=4 --conc_loop=1024 --simul_state=10 --method=CBFS --max_step=50000  --max_deadend=25000 --exp_dir=Result/save_CBFS_syscall/
    rm outputs/*
done

7z a Result/wabot_CBFS.7z Result/save_CBFS_syscall/
rm Result/save_CBFS_syscall/*


for file in Examples/Sample_paper/bancteian/*
do
    python3 Build_SCDG.py $file --eval_time --symb_loop=4 --conc_loop=1024 --simul_state=10 --method=CBFS --max_step=50000  --max_deadend=25000 --exp_dir=Result/save_CBFS_syscall/
    rm outputs/*
done

7z a Result/bancteian_CBFS.7z Result/save_CBFS_syscall/
rm Result/save_CBFS_syscall/*

for file in Examples/Sample_paper/ircbot/*
do
    python3 Build_SCDG.py $file --eval_time --symb_loop=4 --conc_loop=1024 --simul_state=10 --method=CBFS --max_step=50000  --max_deadend=25000 --exp_dir=Result/save_CBFS_syscall/
    rm outputs/*
done

7z a Result/ircbot_CBFS.7z Result/save_CBFS_syscall/
rm Result/save_CBFS_syscall/*

for file in Examples/Sample_paper/FeakerStealer/*
do
    python3 Build_SCDG.py $file --eval_time --symb_loop=4 --conc_loop=1024 --simul_state=10 --method=CBFS --max_step=50000  --max_deadend=25000 --exp_dir=Result/save_CBFS_syscall/
    rm outputs/*
done

7z a Result/FeakerStealer_CBFS.7z Result/save_CBFS_syscall/
rm Result/save_CBFS_syscall/*

for file in Examples/Sample_paper/gandcrab/*
do
    python3 Build_SCDG.py $file --eval_time --symb_loop=4 --conc_loop=1024 --simul_state=10 --method=CBFS --max_step=50000  --max_deadend=25000 --exp_dir=Result/save_CBFS_syscall/
    rm outputs/*
done

7z a Result/gandcrab_CBFS.7z Result/save_CBFS_syscall/
rm Result/save_CBFS_syscall/*

for file in Examples/Sample_paper/lamer/*
do
    python3 Build_SCDG.py $file --eval_time --symb_loop=4 --conc_loop=1024 --simul_state=10 --method=CBFS --max_step=50000  --max_deadend=25000 --exp_dir=Result/save_CBFS_syscall/
    rm outputs/*
done

7z a Result/lamer_CBFS.7z Result/save_CBFS_syscall/
rm Result/save_CBFS_syscall/*

for file in Examples/Sample_paper/NetWire/*
do
    python3 Build_SCDG.py $file --eval_time --symb_loop=4 --conc_loop=1024 --simul_state=10 --method=CBFS --max_step=50000  --max_deadend=25000 --exp_dir=Result/save_CBFS_syscall/
    rm outputs/*
done

7z a Result/NetWire_CBFS.7z Result/save_CBFS_syscall/
rm Result/save_CBFS_syscall/*

for file in Examples/Sample_paper/RedLineStealer/*
do
    python3 Build_SCDG.py $file --eval_time --symb_loop=4 --conc_loop=1024 --simul_state=10 --method=CBFS --max_step=50000  --max_deadend=25000 --exp_dir=Result/save_CBFS_syscall/
    rm outputs/*
done

7z a Result/RedLineStealer_CBFS.7z Result/save_CBFS_syscall/
rm Result/save_CBFS_syscall/*

for file in Examples2/Sample_paper/RemcosRAT/*
do
    python3 Build_SCDG.py $file --eval_time --symb_loop=4 --conc_loop=1024 --simul_state=10 --method=CBFS --max_step=50000  --max_deadend=25000 --exp_dir=Result/save_CBFS_syscall/
    rm outputs/*
done

7z a Result/RemcosRAT_CBFS.7z Result/save_CBFS_syscall/
rm Result/save_CBFS_syscall/*

for file in Examples/Sample_paper/nitol/*
do
    python3 Build_SCDG.py $file --eval_time --symb_loop=4 --conc_loop=1024 --simul_state=10 --method=CBFS --max_step=50000  --max_deadend=25000 --exp_dir=Result/save_CBFS_syscall/
    rm outputs/*
done

7z a Result/nitol_CBFS.7z Result/save_CBFS_syscall/
rm Result/save_CBFS_syscall/*

for file in Examples/Sample_paper/delf/*
do
    python3 Build_SCDG.py $file --eval_time --symb_loop=4 --conc_loop=1024 --simul_state=10 --method=CBFS --max_step=50000  --max_deadend=25000 --exp_dir=Result/save_CBFS_syscall/
    rm outputs/*
done

7z a Result/delf_CBFS.7z Result/save_CBFS_syscall/
rm Result/save_CBFS_syscall/*

for file in Examples2/Sample_paper/upatre/*
do
    python3 Build_SCDG.py $file --eval_time --symb_loop=4 --conc_loop=1024 --simul_state=10 --method=CBFS --max_step=50000  --max_deadend=25000 --exp_dir=Result/save_CBFS_syscall/
    rm outputs/*
done

7z a Result/upatre_CBFS.7z Result/save_CBFS_syscall/
rm Result/save_CBFS_syscall/*
