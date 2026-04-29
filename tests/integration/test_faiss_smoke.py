import pytest
import tempfile


def test_faiss_smoke_index_build_and_persist():
    try:
        import faiss
    except Exception:
        pytest.skip("faiss not installed in this environment")

    import numpy as np

    d = 4
    xb = np.random.random((10, d)).astype('float32')
    xq = np.random.random((2, d)).astype('float32')

    index = faiss.IndexFlatL2(d)
    assert index.is_trained
    index.add(xb)
    assert index.ntotal == xb.shape[0]

    D, I = index.search(xq, k=3)
    assert D.shape == (2, 3)
    assert I.shape == (2, 3)

    # test save/load
    with tempfile.NamedTemporaryFile(suffix='.index') as f:
        faiss.write_index(index, f.name)
        idx2 = faiss.read_index(f.name)
        D2, I2 = idx2.search(xq, k=3)
        assert I2.shape == I.shape
        assert D2.shape == D.shape
