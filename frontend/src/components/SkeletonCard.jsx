export default function SkeletonCard({ className = "", rows = 1 }) {
  return (
    <div className={`skeleton-card ${className}`}>
      {Array.from({ length: rows }, (_, index) => (
        <span key={index} className="skeleton-line" />
      ))}
    </div>
  );
}
