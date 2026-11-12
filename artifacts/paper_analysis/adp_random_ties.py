# Expected ADP under a random order within ties (500 permutations) for lab_paper5 per-node arrays (scores5-*.npz).
# Run: docker run --rm -v <p5/out>:/s:ro -v <outdir>:/o pdp/server:v101rc python3 /o/adp_random_ties.py 500
# The stable-order value reproduces server/pdp_server/tools/darpa_eval.adp.
import numpy as np, glob, sys, json
def adp_curve(lab, att, order):
    l=lab[order]; a=att[order]
    tp=np.cumsum(l); fp=np.cumsum(~l); p=tp/(tp+fp)
    tot=att.any(0).sum() or 1
    # first index at which each attack detected
    first=np.where(a.any(0), np.argmax(a,axis=0), len(l))
    det=np.zeros(len(l)); 
    for f in first[first<len(l)]: det[f:]+=1
    det=100*det/tot
    # max det per unique precision
    xs,inv=np.unique(p,return_inverse=True); ys=np.zeros(len(xs)); np.maximum.at(ys,inv,det)
    xs=np.concatenate([[0.0],xs]); ys=np.concatenate([[0.0],ys])
    if xs[1]==0.0: xs=xs[1:]; ys=ys[1:]; ys[0]=max(ys[0],0)
    return float(np.trapz(ys,xs)/100)
def rand_adp(key, lab, att, n, rng):
    v=[]
    for _ in range(n):
        o=np.lexsort((rng.random(len(key)), -key)); v.append(adp_curve(lab,att,o))
    v=np.array(v); return v.mean(), v.std()/np.sqrt(n)
rng=np.random.default_rng(0); out={}
for f in sorted(glob.glob('/s/scores5-*-r*.npz')):
    z=np.load(f); lab=z['labels'].astype(bool); att=z['attacks']
    if not lab.any(): continue
    tri=z['tier_P2']*1e6+np.clip(z['learned'],0,1e5)
    st=adp_curve(lab,att,np.argsort(-tri,kind='stable'))
    m,se=rand_adp(tri,lab,att,int(sys.argv[1]),rng)
    lm,lse=rand_adp(z['learned'],lab,att,int(sys.argv[1]),rng)
    k=f.split('scores5-')[1][:-4]; out[k]=dict(stable=st,rand=m,se=se,learned_rand=lm,learned_se=lse)
    print(f"{k:34s} stable {st:.3f} random {m:.3f}±{se:.3f} learned random {lm:.3f}±{lse:.3f}",flush=True)
json.dump(out,open('/o/adp_rand.json','w'),indent=1)
