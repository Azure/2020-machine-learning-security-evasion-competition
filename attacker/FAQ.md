<!-- vscode-markdown-toc -->
* 1. [How does the sample `attacker` solution work?](#how-does-the-sample-`attacker`-solution-work?)
* 2. [Can I use adversarial ML toolboxes?](#can-i-use-adversarial-ml-toolboxes?)

<!-- vscode-markdown-toc-config
	numbering=true
	autoSave=true
	/vscode-markdown-toc-config -->
<!-- /vscode-markdown-toc -->

# Frequently Asked Questions

##  1. <a name='how-does-the-sample-`attacker`-solution-work?'></a>How does the sample `attacker` solution work?
The [example solution](attacker/__main__.py) contains code that produces evasive variants. However, it is possible that
1. some of the samples produced may not be functional afterall, or
2. no evasive variant is discovered for a set of samples.

Thus, manual inspection and manipulation of samples may be required.

The [HyperOptAttacker class](attacker/attacker.py#L44) in the example code uses the following strategies:
* [Sequential model-based global optimization](https://papers.nips.cc/paper/4443-algorithms-for-hyper-parameter-optimization.pdf) explores a space of file modifications that decreases the model score, keeping a history of successful and failed strategies via a modeled surrogate of the objective that's updated over time.
* [Functionality-preserving file modifications](attacker/utils/modify.py) should (mostly) preserve the functionality of the files. The following parts of a file can be modified with the example code:
  - add new sections with benign content
  - add additional (unused) imports
  - append data to the file (the overlay)
  - modify the timestamp
* In a generalization of a "happy-strings" attack, content is only _added_ to a file. The content to add is scraped from a set of benign files that the user specifies.

For the optimization, we use the [Tree of Parzen estimators (TPE)](https://papers.nips.cc/paper/4443-algorithms-for-hyper-parameter-optimization.pdf) algorithm built into [hyperopt](https://github.com/hyperopt/hyperopt). To make the problem a tractable optimization problem, we employed the following strategies:
* Parameterize the file modifications. 
  -  For sections and imports, the optimizer may choose _how many_ sections / imports to add. 
  -  For sections, imports, and overlays, the optimizer may choose _which_ benign source to copy from (parameterized by an index) and _how many_ bytes to copy to the target (parameterized by a percentage).
  - A new timestamp may be selected between the minimum and maximum timestamp observed in the benign set (parameterized by a percentage).
* Derive _scores_ from the hard-labeled model outputs to guide the optimization.
  - We average the output of hard-label models. 
  - Additionally, we include in the average the _score_ of a barebones [ember](https://github.com/endgameinc/ember) model, so that the objective function outputs a number between zero and one.


##  2. <a name='can-i-use-adversarial-ml-toolboxes?'></a>Can I use adversarial ML toolboxes?
Short answer: Maybe! Black-box approaches are the appropriate, but be aware that many were designed for images, with norm constraints on the input that may not be suitable for malware.

The [Adversarial Robustness Toolbox](https://github.com/Trusted-AI/adversarial-robustness-toolbox) includes a number of [black-box attacks](https://github.com/Trusted-AI/adversarial-robustness-toolbox/wiki/ART-Attacks#12-black-box). The implementation and constraints in these attacks are primarily tailored for attacking image models.

[SecML](https://gitlab.com/secml/secml) includes attacks and corresponding defenses for several methods under both white-box and black-box threat models.

[CleverHans](https://github.com/tensorflow/cleverhans) focuses primarily on white-box generation of adversarial examples for images, but may provide some guidance in your attack.