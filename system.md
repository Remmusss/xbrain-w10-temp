# W10 Lab - 6-risk Cluster Cleanup + Cluster-level Enforcement

## 1. Mục tiêu cần đạt được

Lab cuối W10 là bài tổng hợp: tìm và dọn 6 rủi ro phổ biến trong cluster, sau đó khóa lại bằng enforcement ở cấp cluster để lỗi không quay lại.

Kết quả cuối lab cần đạt:

- Cluster có 3 role rõ ràng: `developer`, `sre`, `viewer`.
- Có ít nhất 4 Gatekeeper constraint enforce.
- Secret được quản lý qua AWS Secrets Manager và External Secrets Operator.
- Secret rotate dưới 60 giây, workload nhận secret mới không restart.
- CI có scan image bằng Trivy.
- Image được ký bằng Cosign.
- Admission reject image chưa ký.
- Namespace có ResourceQuota và LimitRange.
- Có runbook xử lý sự cố.
- Mini platform có thể deploy end-to-end từ repo trong dưới 2 giờ.

Tinh thần lab: không chỉ sửa từng lỗi một lần, mà phải biến cách sửa thành guardrail để lỗi tương tự bị chặn tự động ở lần sau.

## 2. 6 rủi ro cần cleanup

### Risk 1: RBAC quá rộng

Dấu hiệu:

- User hoặc ServiceAccount dùng `cluster-admin`.
- Developer có quyền đọc secret.
- Developer có quyền sửa Role/RoleBinding.
- Viewer có quyền ghi.

Cần làm:

- Tạo role `developer`, `sre`, `viewer`.
- Scope quyền developer theo namespace.
- Viewer chỉ read-only và không đọc secret.
- SRE có quyền vận hành cần thiết nhưng tránh `cluster-admin`.
- Ghi evidence bằng `kubectl auth can-i`.

Công nghệ:

- Kubernetes RBAC: `Role`, `RoleBinding`, `ClusterRole`, `ClusterRoleBinding`, `ServiceAccount`.

Lý do:

- RBAC là lớp kiểm soát identity gốc của Kubernetes.
- Nếu quyền quá rộng, mọi policy khác có thể bị bypass bằng thao tác admin.

### Risk 2: Pod security yếu

Dấu hiệu:

- Container chạy privileged.
- Container chạy root.
- Root filesystem ghi được.
- Thiếu securityContext.
- Dùng hostPath hoặc hostNetwork không có lý do.

Cần làm:

- Thêm `runAsNonRoot: true`.
- Thêm `allowPrivilegeEscalation: false`.
- Thêm `readOnlyRootFilesystem: true` nếu app hỗ trợ.
- Drop Linux capabilities mặc định.
- Chặn privileged bằng Gatekeeper.

Setting workload đề xuất:

```yaml
securityContext:
  runAsNonRoot: true
  allowPrivilegeEscalation: false
  readOnlyRootFilesystem: true
  capabilities:
    drop:
      - ALL
```

Lý do:

- Giảm blast radius nếu container bị exploit.
- Tiệm cận Kubernetes Pod Security Standards mức restricted.
- Admission enforce giúp developer không vô tình deploy cấu hình nguy hiểm.

### Risk 3: Secret nằm trong Git hoặc inject sai cách

Dấu hiệu:

- Secret value nằm trong YAML.
- `.env` thật bị commit.
- Kubernetes Secret được tạo tay, không có nguồn truth.
- App dùng env var cho secret cần rotate no-restart.

Cần làm:

- Đưa secret gốc vào AWS Secrets Manager.
- Dùng External Secrets Operator để sync sang Kubernetes Secret.
- Mount secret bằng volume nếu cần rotate không restart.
- Không in secret thật trong log/evidence.

Công nghệ:

- AWS Secrets Manager.
- External Secrets Operator.
- Kubernetes Secret volume.
- IRSA hoặc EKS Pod Identity nếu chạy trên EKS.

Setting:

```yaml
refreshInterval: 30s
target:
  creationPolicy: Owner
```

Lý do:

- `refreshInterval: 30s` đáp ứng yêu cầu rotate dưới 60 giây.
- Secret volume có thể được kubelet update, còn env var không tự đổi.
- AWS Secrets Manager có audit/versioning tốt hơn secret copy tay.

### Risk 4: Workload không có resource guard

Dấu hiệu:

- Container thiếu `resources.requests`.
- Container thiếu `resources.limits`.
- Namespace không có quota.
- Một deployment có thể scale vô hạn trong namespace lab.

Cần làm:

- Thêm requests/limits cho container.
- Tạo `ResourceQuota` cho namespace.
- Tạo `LimitRange` để có default/min/max.
- Thêm Gatekeeper constraint bắt buộc requests/limits.

Công nghệ:

- Kubernetes `ResourceQuota`.
- Kubernetes `LimitRange`.
- Gatekeeper constraint.

Setting namespace app-dev đề xuất:

```yaml
hard:
  requests.cpu: "2"
  requests.memory: 4Gi
  limits.cpu: "4"
  limits.memory: 8Gi
  pods: "20"
```

Lý do:

- Scheduler cần request để đặt pod đúng.
- Limit giảm rủi ro workload lỗi chiếm hết tài nguyên.
- Quota giúp lab không vô tình tạo chi phí hoặc áp lực tài nguyên quá lớn.

### Risk 5: Image supply chain không kiểm soát

Dấu hiệu:

- Dùng image `latest`.
- Image không scan CVE.
- Image không ký.
- Cluster cho chạy image từ registry bất kỳ.

Cần làm:

- Dùng tag immutable hoặc digest.
- Scan image bằng Trivy trong CI.
- Fail CI với CRITICAL/HIGH theo policy.
- Ký image bằng Cosign.
- Dùng admission verify signature.
- Chặn unsigned image.

Công nghệ:

- Trivy.
- Cosign/Sigstore.
- Kyverno `verifyImages` hoặc admission policy tương đương.

Lý do:

- Scan bắt lỗi known CVE trước khi deploy.
- Signature chứng minh image đến từ pipeline đáng tin.
- Admission enforcement đảm bảo không ai bypass CI bằng cách apply manifest trực tiếp.

### Risk 6: Thiếu runbook, alert và kiểm thử phục hồi

Dấu hiệu:

- Có alert nhưng không biết xử lý.
- Rollout fail nhưng không có checklist.
- Secret rotation fail nhưng không biết debug lớp nào.
- Không có test pod delete/canary fail.

Cần làm:

- Viết runbook cho ít nhất 3 case: pod compromised, rollout failed, secret rotation failed.
- Thực hành một chaos test nhỏ.
- Ghi lại lệnh kiểm tra và kết quả.
- Liên kết alert hoặc symptom với runbook tương ứng.

Công nghệ:

- Prometheus/Alertmanager nếu dùng từ W9.
- Argo Rollouts cho canary failure.
- `kubectl` cho pod delete test.
- Optional: Litmus hoặc Chaos Mesh nếu muốn chaos framework.

Lý do:

- Platform không chỉ là deploy được, mà còn phải vận hành được khi lỗi xảy ra.
- Runbook biến kiến thức cá nhân thành quy trình đội nhóm.

## 3. Enforcement phải có sau cleanup

### 3.1. Gatekeeper constraint bắt buộc

Tối thiểu cần có 4 constraint enforce:

```text
1. Require workload ownership labels.
2. Disallow privileged containers.
3. Require runAsNonRoot.
4. Require CPU/memory requests and limits.
```

Nên bổ sung:

```text
5. Disallow latest image tag.
6. Restrict hostPath/hostNetwork.
```

Setting:

```yaml
enforcementAction: deny
```

Lý do:

- Lab yêu cầu cluster-level enforcement, không chỉ audit.
- `deny` chứng minh lỗi bị chặn ngay tại admission.

Namespace exclude:

```text
kube-system
gatekeeper-system
argocd
monitoring
external-secrets
kyverno
```

Lý do:

- Namespace hệ thống thường chứa chart/controller có cấu hình đặc thù.
- Policy app nên áp dụng trước cho namespace workload để tránh làm hỏng control plane/addon.

### 3.2. Image signature admission

Yêu cầu:

- Image chưa ký bị reject.
- Image ký sai identity/key bị reject.
- Image ký đúng được accept.

Policy nên giới hạn:

```text
registry được phép
issuer OIDC nếu keyless
subject GitHub Actions workflow nếu keyless
public key nếu key-based
```

Lý do:

- Chỉ kiểm tra "có signature" là chưa đủ nếu ai cũng có thể ký.
- Cần ràng buộc signature với pipeline hoặc key được tin cậy.

## 4. Thiết lập ban đầu

### 4.1. Công cụ cần có

Trên máy làm lab cần:

```text
kubectl
helm
aws cli
docker
trivy
cosign
git
kubectl argo rollouts plugin nếu dùng rollout CLI
```

Kiểm tra:

```powershell
kubectl get nodes
helm version
aws sts get-caller-identity
trivy --version
cosign version
```

### 4.2. Cluster baseline

Cluster cần có:

- Argo CD cho GitOps.
- Gatekeeper cho policy-as-code.
- External Secrets Operator cho secret sync.
- Kyverno hoặc image verification admission.
- Prometheus stack cho observability.
- Argo Rollouts cho canary.

Nếu thiếu controller nào, bootstrap theo thứ tự:

```text
CRD/controller trước
policy/secret custom resource sau
workload cuối cùng
```

Lý do:

- Apply custom resource trước khi CRD tồn tại sẽ fail.
- Workload cần secret/policy/monitoring sẵn để test end-to-end.

### 4.3. Quy ước namespace

Đề xuất:

```text
app-dev
app-prod
argocd
monitoring
gatekeeper-system
external-secrets
kyverno
```

Lý do:

- Tách workload khỏi system controller.
- Policy match/exclude dễ hơn.
- Quota và RBAC theo namespace rõ hơn.

### 4.4. Quy ước label

Workload app phải có:

```yaml
labels:
  app.kubernetes.io/name: demo-api
  app.kubernetes.io/part-of: w10-platform
  owner: <student-or-team>
  environment: dev
```

Lý do:

- Dùng cho ownership, alert routing, cost allocation và incident response.
- Gatekeeper có thể enforce cùng một chuẩn cho mọi workload.

## 5. Cách kiểm thử end-to-end

### 5.1. Test RBAC

```powershell
kubectl auth can-i create deployments -n app-dev --as system:serviceaccount:app-dev:developer-sa
kubectl auth can-i get secrets -n app-dev --as system:serviceaccount:app-dev:developer-sa
kubectl auth can-i delete deployments -n app-dev --as system:serviceaccount:app-dev:viewer-sa
kubectl auth can-i list nodes --as system:serviceaccount:platform-system:sre-sa
```

Kết quả mong muốn:

- Developer create deployment: `yes`.
- Developer get secrets: `no`.
- Viewer delete deployment: `no`.
- SRE list nodes: `yes`.

### 5.2. Test Gatekeeper

Apply manifest sai:

- Thiếu label owner.
- Privileged container.
- Không có requests/limits.
- Chạy root.

Kết quả mong muốn:

- API server reject với message từ Gatekeeper.

Apply manifest đúng:

- Có label.
- Non-root.
- Có requests/limits.
- Không privileged.

Kết quả mong muốn:

- Apply thành công.

### 5.3. Test secret rotation

1. Ghi nhận secret version/hash app đang đọc.
2. Update AWS Secrets Manager.
3. Đợi dưới 60 giây.
4. Gọi app đọc lại hash/version.
5. Kiểm tra pod restart count không tăng.

Kết quả mong muốn:

- Hash/version đổi.
- Pod không restart.
- ESO condition healthy.

### 5.4. Test image admission

Unsigned image:

- Deploy image chưa ký.
- Kết quả: reject.

Signed image:

- Scan bằng Trivy.
- Ký bằng Cosign.
- Deploy manifest dùng image signed.
- Kết quả: accept.

### 5.5. Test quota

Deploy workload vượt quota:

- Quá nhiều replica hoặc request quá cao.
- Kết quả: reject vì quota/limitrange.

Deploy workload hợp lệ:

- Request/limit trong ngưỡng.
- Kết quả: chạy thành công.

### 5.6. Test chaos/runbook

Chọn một:

- Xóa một pod app và quan sát tự phục hồi.
- Deploy canary lỗi và quan sát rollout abort.
- Rotate secret sai quyền và thực hành runbook debug ESO.

Evidence cần ghi:

- Sự cố giả lập.
- Tín hiệu phát hiện.
- Lệnh đã chạy.
- Kết quả.
- Bài học hoặc action item.

## 6. Runbook tối thiểu cần có

### 6.1. Pod compromised

Nội dung:

- Cách xác định pod, image, node.
- Cách lấy log/event.
- Cách cô lập namespace/pod.
- Khi nào scale down.
- Khi nào giữ evidence.
- Cách khôi phục bằng image sạch.

### 6.2. Rollout failed

Nội dung:

- Cách xem Rollout.
- Cách xem AnalysisRun.
- Cách kiểm tra Prometheus query.
- Cách abort/rollback.
- Cách xác nhận stable version phục vụ traffic.

### 6.3. Secret rotation failed

Nội dung:

- Cách kiểm tra AWS Secrets Manager.
- Cách kiểm tra IAM permission.
- Cách kiểm tra ExternalSecret condition.
- Cách kiểm tra Kubernetes Secret update.
- Cách kiểm tra app reload secret.

## 7. Evidence cần nộp

Tối thiểu:

- `kubectl auth can-i` cho 3 role.
- `kubectl get constrainttemplates` và `kubectl get constraints`.
- Log admission reject cho manifest sai.
- ESO sync và rotation dưới 60 giây.
- Trivy scan result.
- Cosign sign/verify result.
- Admission reject unsigned image.
- Quota/LimitRange test.
- Chaos test hoặc runbook drill.
- Thời gian bootstrap fresh cluster.

## 8. Tiêu chí hoàn thành

Lab hoàn thành khi:

- 6 rủi ro đã được nhận diện, sửa và có evidence.
- Ít nhất 4 policy đang enforce ở cấp cluster.
- RBAC thể hiện đúng 3 vai trò.
- Secret lifecycle đi qua AWS Secrets Manager và ESO.
- Supply chain có scan, signing và admission verification.
- Cost/resource guard có ResourceQuota, LimitRange và AWS Cost Anomaly Detection.
- Có runbook đủ để người khác xử lý sự cố theo cùng quy trình.
- Mini platform chạy end-to-end và có thể tái dựng từ repo trong dưới 2 giờ.
